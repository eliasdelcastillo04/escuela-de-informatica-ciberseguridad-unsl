package edu.unsl.ciberlab.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * Controlador de Gamificación CTF (Capture The Flag) para el Laboratorio Purple Team UNSL.
 * Administra los retos incrementales (Red Team y Blue Team) de los 3 módulos centrales
 * (CWE-89, CWE-79, CWE-22) y valida las banderas capturadas por los estudiantes.
 */
@RestController
@RequestMapping("/api/ctf")
public class CtfController {

    private static final Logger log = LoggerFactory.getLogger(CtfController.class);

    public record Challenge(
            String id,
            int moduleNumber,
            String moduleTitle,
            String cwe,
            String team,
            String title,
            String description,
            String hint,
            int points,
            String flag
    ) {}

    private static final List<Challenge> CHALLENGES = List.of(
            new Challenge(
                    "m1-red",
                    1,
                    "Módulo 1: Inyección SQL",
                    "CWE-89",
                    "RED",
                    "Bypass de Autenticación SQLi",
                    "Explota la concatenación SQL en el directorio de usuarios para volcar toda la tabla y exponer credenciales y SSN.",
                    "Prueba ingresar ' OR '1'='1 en el buscador en modo Vulnerable.",
                    100,
                    "FLAG{UNSL_SQLI_AUTH_BYPASS_2026}"
            ),
            new Challenge(
                    "m1-blue",
                    1,
                    "Módulo 1: Inyección SQL",
                    "CWE-89",
                    "BLUE",
                    "Blindaje con PreparedStatement",
                    "Ejecuta la consulta en modo Seguro (PreparedStatement) verificando que la inyección sea tratada como literal y no se filtren passwords ni SSN.",
                    "Cambia el módulo a modo Seguro y envía el payload de ataque para verificar la remediación.",
                    150,
                    "FLAG{UNSL_PREPARED_STATEMENT_DEFENDER_2026}"
            ),
            new Challenge(
                    "m2-red",
                    2,
                    "Módulo 2: Cross-Site Scripting (XSS)",
                    "CWE-79",
                    "RED",
                    "Inyección XSS Reflejada en el DOM",
                    "Inyecta una etiqueta HTML ejecutable (como <script> o <img onerror=...>) en el saludo de perfil sin sanitización.",
                    "Envía <img src=x onerror=\"alert('XSS')\"> en el Módulo 2 en modo Vulnerable.",
                    100,
                    "FLAG{UNSL_XSS_DOM_INJECTION_ALERT_2026}"
            ),
            new Challenge(
                    "m2-blue",
                    2,
                    "Módulo 2: Cross-Site Scripting (XSS)",
                    "CWE-79",
                    "BLUE",
                    "Codificación Contextual y CSP",
                    "Activa el modo Seguro para aplicar Encode.forHtml() y verificar la presencia de Content-Security-Policy: script-src 'none'.",
                    "Envía el payload XSS en modo Seguro y revisa la telemetría de cabeceras HTTP.",
                    150,
                    "FLAG{UNSL_CSP_CONTEXTUAL_ENCODING_2026}"
            ),
            new Challenge(
                    "m3-red",
                    3,
                    "Módulo 3: Path Traversal",
                    "CWE-22",
                    "RED",
                    "Escape de Directorio POSIX",
                    "Utiliza secuencias relativas ../ para escapar del directorio /public/ y leer el archivo confidencial flag.txt.",
                    "Solicita el archivo ../confidential/flag.txt en modo Vulnerable.",
                    150,
                    "FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}"
            ),
            new Challenge(
                    "m3-blue",
                    3,
                    "Módulo 3: Path Traversal",
                    "CWE-22",
                    "BLUE",
                    "Normalización Canónica y Frontera",
                    "Verifica que la validación con Path.normalize() y startsWith() bloquee el intento de escape devolviendo HTTP 403 Forbidden.",
                    "Solicita ../confidential/flag.txt en modo Seguro para obtener la bandera de defensa.",
                    200,
                    "FLAG{UNSL_CANONICAL_PATH_BOUNDARY_2026}"
            )
    );

    /**
     * Lista todos los retos disponibles sin exponer las banderas reales.
     */
    @GetMapping("/challenges")
    public ResponseEntity<Map<String, Object>> getChallenges() {
        List<Map<String, Object>> publicChallenges = new ArrayList<>();
        int totalPoints = 0;

        for (Challenge c : CHALLENGES) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", c.id());
            item.put("moduleNumber", c.moduleNumber());
            item.put("moduleTitle", c.moduleTitle());
            item.put("cwe", c.cwe());
            item.put("team", c.team());
            item.put("title", c.title());
            item.put("description", c.description());
            item.put("hint", c.hint());
            item.put("points", c.points());
            publicChallenges.add(item);
            totalPoints += c.points();
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("totalChallenges", publicChallenges.size());
        response.put("maxPoints", totalPoints);
        response.put("challenges", publicChallenges);
        return ResponseEntity.ok(response);
    }

    /**
     * Valida una bandera enviada por el estudiante desde el portal web o la terminal MS-DOS.
     */
    @PostMapping("/submit")
    public ResponseEntity<Map<String, Object>> submitFlag(@RequestBody Map<String, String> payload) {
        String submittedFlag = payload.getOrDefault("flag", "").trim();

        if (submittedFlag.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "valid", false,
                    "message", "Debe ingresar una bandera con formato FLAG{...}."
            ));
        }

        Optional<Challenge> matched = CHALLENGES.stream()
                .filter(c -> c.flag().equals(submittedFlag))
                .findFirst();

        if (matched.isPresent()) {
            Challenge c = matched.get();
            log.info("[CTF - VALIDACIÓN EXITOSA] Reto {} ({}) resuelto. +{} pts", c.id(), c.team(), c.points());

            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("valid", true);
            ok.put("challengeId", c.id());
            ok.put("moduleNumber", c.moduleNumber());
            ok.put("team", c.team());
            ok.put("title", c.title());
            ok.put("points", c.points());
            ok.put("message", "¡Bandera correcta! Reto '" + c.title() + "' completado (+" + c.points() + " pts).");
            return ResponseEntity.ok(ok);
        }

        log.warn("[CTF - BANDERA INVÁLIDA] Intento fallido: {}", submittedFlag);
        return ResponseEntity.badRequest().body(Map.of(
                "valid", false,
                "message", "Bandera incorrecta o no reconocida. Revisa la fase actual e intenta nuevamente."
        ));
    }

    /**
     * Retorna metadatos de estado del motor CTF.
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("labName", "Laboratorio de Ciberseguridad Web - UNSL");
        status.put("approach", "Purple Team Incremental (Red + Blue)");
        status.put("totalChallenges", CHALLENGES.size());
        status.put("totalModules", 3);
        status.put("maxScore", CHALLENGES.stream().mapToInt(Challenge::points).sum());
        return ResponseEntity.ok(status);
    }
}
