package edu.unsl.ciberlab.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Servicio centralizado en memoria (thread-safe) para coordinar:
 * 1. La jornada activa del taller (DIA_1, DIA_2, DIA_3_CTF, LIBRE).
 * 2. El Modo Demo Docente (habilita botones de payload rápido solo para demostración).
 * 3. El registro de estudiantes y el Ranking CTF en tiempo real para el Día 3.
 */
@Service
public class ClassroomStateService {

    public enum WorkshopPhase {
        DIA_1("Día 1: Path Traversal y SQLi (Parte 1)"),
        DIA_2("Día 2: SQLi (Parte 2) y XSS Reflejado/Almacenado"),
        DIA_3_CTF("Día 3: Competencia Capture The Flag (CTF)"),
        LIBRE("Modo Libre: Todas las jornadas habilitadas");

        private final String label;

        WorkshopPhase(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    public static final class Participant {
        private final String sessionId;
        private String alias;
        private String workstation;
        private int totalPoints;
        private final Set<String> solvedChallengeIds = ConcurrentHashMap.newKeySet();
        private final Set<String> passedQuizzes = ConcurrentHashMap.newKeySet();
        private long lastSolveEpochMs;
        private final long registeredAtEpochMs;

        public Participant(String sessionId, String alias, String workstation) {
            this.sessionId = sessionId;
            this.alias = alias;
            this.workstation = workstation;
            this.registeredAtEpochMs = System.currentTimeMillis();
            this.lastSolveEpochMs = this.registeredAtEpochMs;
        }

        public String getSessionId() { return sessionId; }
        public synchronized String getAlias() { return alias; }
        public synchronized void setAlias(String alias) { this.alias = alias; }
        public synchronized String getWorkstation() { return workstation; }
        public synchronized void setWorkstation(String workstation) { this.workstation = workstation; }
        public synchronized int getTotalPoints() { return totalPoints; }
        public Set<String> getSolvedChallengeIds() { return solvedChallengeIds; }
        public Set<String> getPassedQuizzes() { return passedQuizzes; }
        public synchronized long getLastSolveEpochMs() { return lastSolveEpochMs; }
        public long getRegisteredAtEpochMs() { return registeredAtEpochMs; }

        public synchronized boolean recordSolve(String challengeId, int points) {
            if (solvedChallengeIds.add(challengeId)) {
                this.totalPoints += points;
                this.lastSolveEpochMs = System.currentTimeMillis();
                return true;
            }
            return false;
        }

        public synchronized void resetScore() {
            this.totalPoints = 0;
            this.solvedChallengeIds.clear();
            this.lastSolveEpochMs = System.currentTimeMillis();
        }
    }

    private volatile WorkshopPhase activePhase = WorkshopPhase.LIBRE;
    private volatile boolean demoModeEnabled = false;
    private volatile boolean ctfUnlocked = false;
    private volatile long competitionStartEpochMs = System.currentTimeMillis();
    private final Map<String, Participant> participants = new ConcurrentHashMap<>();

    public WorkshopPhase getActivePhase() {
        return activePhase;
    }

    public void setActivePhase(WorkshopPhase activePhase) {
        this.activePhase = activePhase;
    }

    public boolean isDemoModeEnabled() {
        return demoModeEnabled;
    }

    public void setDemoModeEnabled(boolean demoModeEnabled) {
        this.demoModeEnabled = demoModeEnabled;
    }

    public boolean isCtfUnlocked() {
        return ctfUnlocked;
    }

    public void setCtfUnlocked(boolean ctfUnlocked) {
        if (ctfUnlocked && !this.ctfUnlocked) {
            this.competitionStartEpochMs = System.currentTimeMillis();
        }
        this.ctfUnlocked = ctfUnlocked;
    }

    public Participant registerOrUpdateParticipant(String sessionId, String alias, String workstation) {
        String cleanId = (sessionId == null || sessionId.isBlank())
                ? UUID.randomUUID().toString()
                : sessionId.trim().replaceAll("[^a-zA-Z0-9_-]", "");
        if (cleanId.isEmpty()) {
            cleanId = UUID.randomUUID().toString();
        }
        String cleanAlias = sanitizeLabel(alias, "Estudiante-" + cleanId.substring(0, Math.min(4, cleanId.length())), 32);
        String cleanPc = sanitizeLabel(workstation, "Sala-UNSL", 20);

        final String finalId = cleanId;
        return participants.compute(finalId, (k, existing) -> {
            if (existing == null) {
                return new Participant(finalId, cleanAlias, cleanPc);
            }
            existing.setAlias(cleanAlias);
            existing.setWorkstation(cleanPc);
            return existing;
        });
    }

    public Optional<Participant> findParticipant(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(participants.get(sessionId.trim()));
    }

    public List<Map<String, Object>> getLeaderboard() {
        List<Participant> list = new ArrayList<>(participants.values());
        list.sort(Comparator
                .comparingInt(Participant::getTotalPoints).reversed()
                .thenComparingLong(Participant::getLastSolveEpochMs)
                .thenComparing(Participant::getAlias, String.CASE_INSENSITIVE_ORDER));

        List<Map<String, Object>> rows = new ArrayList<>();
        int rank = 1;
        java.time.format.DateTimeFormatter timeFmt = java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")
                .withZone(java.time.ZoneId.systemDefault());
        for (Participant p : list) {
            long elapsedSec = p.getSolvedChallengeIds().isEmpty()
                    ? 0L
                    : Math.max(0L, (p.getLastSolveEpochMs() - competitionStartEpochMs) / 1000L);
            String elapsedFormatted = p.getSolvedChallengeIds().isEmpty()
                    ? "--:--"
                    : formatDuration(elapsedSec);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("rank", rank++);
            row.put("sessionId", p.getSessionId());
            row.put("alias", p.getAlias());
            row.put("workstation", p.getWorkstation());
            row.put("points", p.getTotalPoints());
            row.put("solvedCount", p.getSolvedChallengeIds().size());
            row.put("solvedChallenges", new ArrayList<>(p.getSolvedChallengeIds()));
            row.put("passedQuizzes", new ArrayList<>(p.getPassedQuizzes()));
            row.put("elapsedSeconds", elapsedSec);
            row.put("elapsedFormatted", elapsedFormatted);
            row.put("lastSolveTime", timeFmt.format(Instant.ofEpochMilli(p.getLastSolveEpochMs())));
            row.put("lastSolveIso", Instant.ofEpochMilli(p.getLastSolveEpochMs()).toString());
            rows.add(row);
        }
        return rows;
    }

    public void resetLeaderboardScores() {
        this.competitionStartEpochMs = System.currentTimeMillis();
        participants.values().forEach(Participant::resetScore);
    }

    private String formatDuration(long totalSeconds) {
        long hours = totalSeconds / 3600;
        long mins = (totalSeconds % 3600) / 60;
        long secs = totalSeconds % 60;
        if (hours > 0) {
            return String.format("%dh %02dm %02ds", hours, mins, secs);
        }
        return String.format("%02dm %02ds", mins, secs);
    }

    public Map<String, Object> getStateSnapshot() {
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("activePhase", activePhase.name());
        state.put("phaseLabel", activePhase.getLabel());
        state.put("demoModeEnabled", demoModeEnabled);
        state.put("ctfUnlocked", ctfUnlocked);
        state.put("totalParticipants", participants.size());
        return state;
    }

    private String sanitizeLabel(String raw, String fallback, int maxLen) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        String trimmed = raw.trim().replaceAll("[<>\"'&]", "");
        if (trimmed.isEmpty()) {
            return fallback;
        }
        return trimmed.length() > maxLen ? trimmed.substring(0, maxLen) : trimmed;
    }
}
