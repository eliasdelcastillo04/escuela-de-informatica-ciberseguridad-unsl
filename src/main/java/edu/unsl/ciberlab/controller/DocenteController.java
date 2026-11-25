package edu.unsl.ciberlab.controller;

import edu.unsl.ciberlab.service.ClassroomStateService;
import edu.unsl.ciberlab.service.ClassroomStateService.WorkshopPhase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Controlador de administración docente para la Sala de Máquinas.
 * Permite habilitar jornadas (Día 1, Día 2, Día 3 CTF), activar Modo Demo,
 * reiniciar el Ranking CTF y exportar resultados en CSV.
 */
@RestController
@RequestMapping("/api")
public class DocenteController {

    private static final Logger log = LoggerFactory.getLogger(DocenteController.class);

    private final ClassroomStateService classroomState;
    private final String docentePassword;

    public DocenteController(
            ClassroomStateService classroomState,
            @Value("${app.docente.password:unsl-docente-2026}") String docentePassword) {
        this.classroomState = classroomState;
        this.docentePassword = docentePassword;
    }

    @GetMapping("/classroom/state")
    public ResponseEntity<Map<String, Object>> getClassroomState() {
        return ResponseEntity.ok(classroomState.getStateSnapshot());
    }

    @PostMapping("/docente/auth")
    public ResponseEntity<Map<String, Object>> authenticate(@RequestBody Map<String, String> payload) {
        String pwd = payload.getOrDefault("password", "");
        if (!isAuthorized(pwd)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "authenticated", false,
                    "message", "Clave docente incorrecta."
            ));
        }
        return ResponseEntity.ok(Map.of(
                "authenticated", true,
                "state", classroomState.getStateSnapshot()
        ));
    }

    @PostMapping("/docente/phase")
    public ResponseEntity<Map<String, Object>> updatePhase(
            @RequestHeader(value = "X-Docente-Password", required = false) String headerPwd,
            @RequestBody Map<String, Object> payload) {

        String pwd = headerPwd != null ? headerPwd : String.valueOf(payload.getOrDefault("password", ""));
        if (!isAuthorized(pwd)) {
            return unauthorizedResponse();
        }

        if (payload.containsKey("phase")) {
            try {
                WorkshopPhase phase = WorkshopPhase.valueOf(String.valueOf(payload.get("phase")).trim().toUpperCase());
                classroomState.setActivePhase(phase);
                log.info("[DOCENTE] Jornada activa cambiada a: {}", phase);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(Map.of("error", "Jornada inválida. Use DIA_1, DIA_2, DIA_3_CTF o LIBRE."));
            }
        }

        if (payload.containsKey("demoMode")) {
            boolean demo = Boolean.parseBoolean(String.valueOf(payload.get("demoMode")));
            classroomState.setDemoModeEnabled(demo);
            log.info("[DOCENTE] Modo Demo Docente: {}", demo ? "ACTIVADO" : "DESACTIVADO");
        }

        if (payload.containsKey("ctfUnlocked")) {
            boolean ctf = Boolean.parseBoolean(String.valueOf(payload.get("ctfUnlocked")));
            classroomState.setCtfUnlocked(ctf);
            log.info("[DOCENTE] Competencia CTF: {}", ctf ? "LIBERADA" : "OCULTA");
        }

        return ResponseEntity.ok(classroomState.getStateSnapshot());
    }

    @PostMapping("/docente/reset-leaderboard")
    public ResponseEntity<Map<String, Object>> resetLeaderboard(
            @RequestHeader(value = "X-Docente-Password", required = false) String headerPwd,
            @RequestBody(required = false) Map<String, String> payload) {

        String pwd = headerPwd != null ? headerPwd : (payload != null ? payload.getOrDefault("password", "") : "");
        if (!isAuthorized(pwd)) {
            return unauthorizedResponse();
        }

        classroomState.resetLeaderboardScores();
        log.info("[DOCENTE] Puntajes del Ranking CTF reiniciados para nueva competencia.");
        return ResponseEntity.ok(Map.of(
                "reset", true,
                "message", "Ranking CTF reiniciado correctamente.",
                "state", classroomState.getStateSnapshot()
        ));
    }

    @GetMapping("/docente/export-csv")
    public ResponseEntity<?> exportLeaderboardCsv(
            @RequestHeader(value = "X-Docente-Password", required = false) String headerPwd,
            @RequestParam(value = "password", required = false) String queryPwd) {

        String pwd = headerPwd != null ? headerPwd : (queryPwd != null ? queryPwd : "");
        if (!isAuthorized(pwd)) {
            return unauthorizedResponse();
        }

        List<Map<String, Object>> rows = classroomState.getLeaderboard();
        StringBuilder csv = new StringBuilder();
        csv.append("Puesto,Alias,PuestoTrabajo,Puntaje,RetosResueltos,QuizzesAprobados,UltimaCaptura\n");
        for (Map<String, Object> row : rows) {
            csv.append(row.get("rank")).append(',')
               .append(escapeCsv(String.valueOf(row.get("alias")))).append(',')
               .append(escapeCsv(String.valueOf(row.get("workstation")))).append(',')
               .append(row.get("points")).append(',')
               .append(row.get("solvedCount")).append(',')
               .append(((List<?>) row.get("passedQuizzes")).size()).append(',')
               .append(escapeCsv(String.valueOf(row.get("lastSolveIso")))).append('\n');
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(new MediaType("text", "csv", StandardCharsets.UTF_8));
        headers.setContentDispositionFormData("attachment", "ranking_ciberlab_unsl.csv");
        return ResponseEntity.ok().headers(headers).body(csv.toString());
    }

    private boolean isAuthorized(String provided) {
        return provided != null && !provided.isBlank() && provided.equals(docentePassword);
    }

    private ResponseEntity<Map<String, Object>> unauthorizedResponse() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "error", "UNAUTHORIZED",
                "message", "Se requiere autenticación docente válida."
        ));
    }

    private String escapeCsv(String val) {
        String clean = val.replace("\"", "\"\"");
        return "\"" + clean + "\"";
    }
}
