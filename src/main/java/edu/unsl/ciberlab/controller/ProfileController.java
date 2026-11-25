package edu.unsl.ciberlab.controller;

import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * MÓDULO 3 (DÍA 2): CWE-79 (Cross-Site Scripting - Reflected & Stored)
 * - XSS Reflejado (/api/profile/greet): Demuestra ejecución en el DOM y exposición de sesión simulada.
 * - XSS Almacenado (/api/profile/notes): Persiste en H2 aislado por sesión de estudiante (X-Lab-Session)
 *   para evitar contaminación cruzada entre compañeros en la Sala de Máquinas.
 * - Blue Team: OWASP Java Encoder (Encode.forHtml) + cabeceras Content-Security-Policy (CSP).
 */
@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private static final Logger log = LoggerFactory.getLogger(ProfileController.class);
    private static final int MAX_NOTES_PER_SESSION = 20;
    private static final int MAX_NOTE_LENGTH = 500;

    private final JdbcTemplate jdbcTemplate;

    public ProfileController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> greetUser(
            @RequestParam(name = "name", defaultValue = "Invitado") String name,
            @RequestParam(name = "mode", defaultValue = "vuln") String mode) {

        if ("safe".equalsIgnoreCase(mode)) {
            return greetUserRemediated(name);
        }

        log.warn("[Purple Team - ALERTA CWE-79] Reflejando entrada cruda sin sanitizar: {}", name);

        String htmlVulnerable = """
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <title>Portal Universitario - Saludo de Perfil</title>
                <style>
                    body { font-family: system-ui, sans-serif; padding: 1.25rem; background: #fff; color: #111; margin: 0; }
                    .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 1.15rem; max-width: 620px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
                    .badge-vuln { background: #fee2e2; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.78rem; }
                    .telemetry { margin-top: 0.85rem; font-family: monospace; font-size: 0.8rem; background: #f3f4f6; padding: 0.7rem; border-radius: 4px; }
                    .session-box { margin-top: 0.75rem; font-family: monospace; font-size: 0.78rem; background: #fffbeb; border: 1px solid #fde68a; color: #92400e; padding: 0.55rem 0.7rem; border-radius: 4px; }
                </style>
                <script>
                    // Sesión simulada accesible al DOM (sin HttpOnly) para demostrar impacto de XSS
                    window.__SIU_DEMO_SESSION__ = "SIU_SID=UNSL-2026-DEMO-TOKEN";
                </script>
            </head>
            <body>
                <div class="card">
                    <span class="badge-vuln">ESTADO: MODO VULNERABLE (CWE-79)</span>
                    <h2 style="margin: 10px 0 6px;">¡Bienvenido/a a la plataforma, %s!</h2>
                    <p style="margin: 0;">Tu sesión de entrenamiento Purple Team está actualmente activa.</p>
                    <div class="session-box">
                        Token de sesión activo en contexto JS (sin HttpOnly): <strong>SIU_SID=UNSL-2026-DEMO-TOKEN</strong>
                    </div>
                    <div class="telemetry">
                        <strong>Telemetría HTTP Servidor:</strong><br>
                        Entrada recibida: %s<br>
                        Cabecera Content-Security-Policy: [NO ESTABLECIDA]<br>
                        Escape contextual: NINGUNO
                    </div>
                </div>
            </body>
            </html>
            """.formatted(name, name);

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-PurpleTeam-Mode", "VULNERABLE (CWE-79)");
        headers.set("X-PurpleTeam-Sanitization", "NONE");
        headers.set("X-PurpleTeam-CSP", "ABSENT");
        if (containsXssPayload(name)) {
            headers.set("X-PurpleTeam-Red-Flag", "FLAG{UNSL_XSS_DOM_INJECTION_ALERT_2026}");
        }

        return ResponseEntity.ok()
                .headers(headers)
                .body(htmlVulnerable);
    }

    public ResponseEntity<String> greetUserRemediated(String name) {
        log.info("[Purple Team - REMEDIADO] Aplicando sanitización contextual Encode.forHtml() y cabeceras CSP");

        String safeName = Encode.forHtml(name);

        String htmlRemediated = """
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <title>Portal Universitario - Saludo de Perfil (Seguro)</title>
                <style>
                    body { font-family: system-ui, sans-serif; padding: 1.25rem; background: #fff; color: #111; margin: 0; }
                    .card { border: 1px solid #bbf7d0; border-radius: 8px; padding: 1.15rem; max-width: 620px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
                    .badge-safe { background: #dcfce7; color: #166534; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.78rem; }
                    .telemetry { margin-top: 0.85rem; font-family: monospace; font-size: 0.8rem; background: #f0fdf4; padding: 0.7rem; border-radius: 4px; border: 1px solid #bbf7d0; }
                </style>
            </head>
            <body>
                <div class="card">
                    <span class="badge-safe">ESTADO: REMEDIADO (Encode.forHtml + CSP)</span>
                    <h2 style="margin: 10px 0 6px;">¡Bienvenido/a a la plataforma, %s!</h2>
                    <p style="margin: 0;">Tu saludo ha sido sanitizado contextualmente contra inyecciones XSS.</p>
                    <div class="telemetry">
                        <strong>Telemetría Defensiva Aplicada:</strong><br>
                        Entrada original: %s<br>
                        Entidad HTML codificada: %s<br>
                        Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none';<br>
                        X-Content-Type-Options: nosniff
                    </div>
                </div>
            </body>
            </html>
            """.formatted(safeName, Encode.forHtmlContent(name), safeName);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-PurpleTeam-Mode", "REMEDIATED (CWE-79 Mitigated)");
        headers.set("X-PurpleTeam-Sanitization", "OWASP Encode.forHtml");
        headers.set("X-PurpleTeam-CSP", "default-src 'self'; script-src 'none'; object-src 'none'");
        headers.set("X-PurpleTeam-Blue-Flag", "FLAG{UNSL_CSP_CONTEXTUAL_ENCODING_2026}");

        return ResponseEntity.ok()
                .headers(headers)
                .body(htmlRemediated);
    }

    /**
     * Lista las notas almacenadas en servidor para la sesión actual del estudiante.
     */
    @GetMapping("/notes")
    public ResponseEntity<Map<String, Object>> listNotes(
            @RequestHeader(value = "X-Lab-Session", required = false, defaultValue = "default") String sessionId) {

        String cleanSession = normalizeSessionId(sessionId);
        List<Map<String, Object>> notes = jdbcTemplate.queryForList(
                "SELECT id, author, content, created_at FROM profile_notes WHERE session_id = ? ORDER BY id ASC",
                cleanSession
        );

        return ResponseEntity.ok(Map.of(
                "sessionId", cleanSession,
                "notes", notes,
                "total", notes.size()
        ));
    }

    /**
     * Guarda una observación en la base de datos H2 (XSS Almacenado aislado por sesión).
     */
    @PostMapping("/notes")
    public ResponseEntity<Map<String, Object>> createNote(
            @RequestHeader(value = "X-Lab-Session", required = false, defaultValue = "default") String sessionId,
            @RequestBody Map<String, String> payload) {

        String cleanSession = normalizeSessionId(sessionId);
        String rawContent = payload.getOrDefault("content", "").trim();
        String author = payload.getOrDefault("author", "Alumno UNSL").trim();
        String mode = payload.getOrDefault("mode", "vuln").trim();

        if (rawContent.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "El contenido de la observación no puede estar vacío."));
        }
        if (rawContent.length() > MAX_NOTE_LENGTH) {
            rawContent = rawContent.substring(0, MAX_NOTE_LENGTH);
        }
        String cleanAuthor = Encode.forHtml(author.length() > 50 ? author.substring(0, 50) : author);

        Integer currentCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM profile_notes WHERE session_id = ?",
                Integer.class,
                cleanSession
        );
        if (currentCount != null && currentCount >= MAX_NOTES_PER_SESSION) {
            jdbcTemplate.update(
                    "DELETE FROM profile_notes WHERE id = (SELECT MIN(id) FROM profile_notes WHERE session_id = ?)",
                    cleanSession
            );
        }

        boolean safeMode = "safe".equalsIgnoreCase(mode);
        String storedContent = safeMode ? Encode.forHtml(rawContent) : rawContent;
        String nowTime = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));

        jdbcTemplate.update(
                "INSERT INTO profile_notes (session_id, author, content, created_at) VALUES (?, ?, ?, ?)",
                cleanSession, cleanAuthor, storedContent, nowTime
        );

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("saved", true);
        response.put("mode", safeMode ? "REMEDIATED (OWASP Encode.forHtml)" : "VULNERABLE (Raw Stored)");
        response.put("storedContent", storedContent);

        if (!safeMode && containsXssPayload(rawContent)) {
            response.put("redTeamFlag", "FLAG{UNSL_STORED_XSS_PERSISTENT_2026}");
        } else if (safeMode) {
            response.put("blueTeamFlag", "FLAG{UNSL_CSP_CONTEXTUAL_ENCODING_2026}");
        }

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/notes")
    public ResponseEntity<Map<String, Object>> clearNotes(
            @RequestHeader(value = "X-Lab-Session", required = false, defaultValue = "default") String sessionId) {

        String cleanSession = normalizeSessionId(sessionId);
        int deleted = jdbcTemplate.update("DELETE FROM profile_notes WHERE session_id = ?", cleanSession);
        return ResponseEntity.ok(Map.of("cleared", true, "deletedCount", deleted));
    }

    private boolean containsXssPayload(String input) {
        if (input == null) return false;
        String lower = input.toLowerCase();
        return lower.contains("<script")
                || lower.contains("onerror")
                || lower.contains("onload")
                || lower.contains("<svg")
                || lower.contains("<img");
    }

    private String normalizeSessionId(String raw) {
        if (raw == null || raw.isBlank()) return "default";
        String clean = raw.trim().replaceAll("[^a-zA-Z0-9_-]", "");
        if (clean.isEmpty()) return "default";
        return clean.length() > 64 ? clean.substring(0, 64) : clean;
    }
}
