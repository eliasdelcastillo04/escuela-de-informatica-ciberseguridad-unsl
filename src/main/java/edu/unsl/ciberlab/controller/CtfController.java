package edu.unsl.ciberlab.controller;

import edu.unsl.ciberlab.service.ClassroomStateService;
import edu.unsl.ciberlab.service.ClassroomStateService.Participant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * Controlador de Gamificación CTF, Registro de Participantes, Ranking en Tiempo Real
 * y Cuestionarios Formativos para las 3 jornadas del Taller Purple Team UNSL.
 */
@RestController
@RequestMapping("/api/ctf")
public class CtfController {

    private static final Logger log = LoggerFactory.getLogger(CtfController.class);

    public record Challenge(
            String id,
            int moduleNumber,
            int dayNumber,
            String moduleTitle,
            String cwe,
            String team,
            String title,
            String description,
            String hint,
            int points,
            String flag
    ) {}

    public record QuizQuestion(
            String id,
            String prompt,
            List<String> options,
            int correctIndex,
            String explanation
    ) {}

    public record ChainStep(
            int stepOrder,
            String challengeId,
            String title,
            String cwe,
            int points,
            String briefing,
            String didacticNote,
            List<String> conceptualHints,
            String suggestedCurl,
            String endpointType,
            String nextHint
    ) {}

    private static final List<ChainStep> CHAIN_STEPS = List.of(
            new ChainStep(
                    1, "m1-red", "PASO 1 // Reconocimiento: Escape de Directorio", "CWE-22", 100,
                    "El portal público descarga documentos con /api/files/download?filename=... Escapa de /public/ hacia /confidential/ para leer flag.txt.",
                    "Por qué funciona: concatenar rutas sin Path.normalize() ni startsWith() permite subir niveles con '../'.",
                    List.of(
                            "Pista 1: En Linux, '../' sube un directorio padre.",
                            "Pista 2: Desde /storage/public/, sube un nivel y apunta a confidential/flag.txt."
                    ),
                    "curl -s \"http://localhost:8080/api/files/download?filename=../confidential/flag.txt&mode=vuln\"",
                    "file",
                    "Pista hacia el Paso 2: En la misma carpeta confidential/ existe un respaldo interno de Sala 8 llamado 'ctf_day3_audit.txt'."
            ),
            new ChainStep(
                    2, "ctf-backup", "PASO 2 // Respaldo Oculto de Sala 8", "CWE-22", 200,
                    "Aplica la pista del Paso 1 para leer el archivo de respaldo interno de Sala 8 y obtener su bandera.",
                    "Por qué importa: un Path Traversal expone archivos de configuración, respaldos y credenciales fuera del root web.",
                    List.of(
                            "Pista 1: Usa el mismo endpoint /api/files/download en mode=vuln.",
                            "Pista 2: Cambia el nombre del archivo a ../confidential/ctf_day3_audit.txt."
                    ),
                    "curl -s \"http://localhost:8080/api/files/download?filename=../confidential/ctf_day3_audit.txt&mode=vuln\"",
                    "file",
                    "Pista hacia el Paso 3: Los registros internos revelan que /api/users/search?username= concatena SQL directamente. Fuerza un Auth Bypass booleano."
            ),
            new ChainStep(
                    3, "m2-red", "PASO 3 // Bypass de Autenticación SQLi", "CWE-89", 100,
                    "Explota la concatenación SQL en /api/users/search para volcar toda la tabla 'users' y capturar la bandera.",
                    "Por qué funciona: una comilla simple cierra el literal SQL y 'OR 1=1' vuelve verdadera la cláusula WHERE para todas las filas.",
                    List.of(
                            "Pista 1: Cierra la comilla simple de username='...' e inyecta un operador lógico OR.",
                            "Pista 2: Prueba el payload clásico: ' OR '1'='1"
                    ),
                    "curl -s \"http://localhost:8080/api/users/search?username=%27%20OR%20%271%27%3D%271&mode=vuln\"",
                    "sql",
                    "Pista hacia el Paso 4: La consulta proyecta 5 columnas. Existe una tabla secundaria 'audit_secrets' (id, code_name, secret_value, classification). Usa UNION SELECT."
            ),
            new ChainStep(
                    4, "ctf-schema", "PASO 4 // Cazador de Esquemas (UNION SQLi)", "CWE-89", 250,
                    "Combina la consulta original de 5 columnas con UNION SELECT sobre 'audit_secrets' para extraer CTF_DAY3_DB_KEY.",
                    "Por qué funciona: UNION une dos SELECT con igual cantidad de columnas, exponiendo tablas distintas a la consultada originalmente.",
                    List.of(
                            "Pista 1: audit_secrets tiene 4 columnas; agrega una 5ta columna literal (ej. 'x') para igualar las 5 de users.",
                            "Pista 2: ' UNION SELECT id, code_name, secret_value, classification, 'x' FROM audit_secrets--"
                    ),
                    "curl -s --get --data-urlencode \"username=' UNION SELECT id, code_name, secret_value, classification, 'x' FROM audit_secrets--\" \"http://localhost:8080/api/users/search?mode=vuln\"",
                    "sql",
                    "Pista hacia el Paso 5: El último vector ofensivo está en /api/profile/greet?name=, que refleja HTML sin Encode.forHtml() ni CSP."
            ),
            new ChainStep(
                    5, "m3-red", "PASO 5 // Inyección XSS en el DOM", "CWE-79", 100,
                    "Inyecta una etiqueta HTML ejecutable en /api/profile/greet?name= (mode=vuln) para capturar la bandera en la cabecera X-PurpleTeam-Red-Flag.",
                    "Por qué funciona: sin codificación contextual ni CSP, el navegador interpreta tu entrada como código ejecutable.",
                    List.of(
                            "Pista 1: Envía una etiqueta como <img src=x onerror=\"alert('XSS')\"> o <script>...",
                            "Pista 2: Revisa las cabeceras de respuesta HTTP (X-PurpleTeam-Red-Flag)."
                    ),
                    "curl -i --get --data-urlencode \"name=<img src=x onerror=alert(1)>\" \"http://localhost:8080/api/profile/greet?mode=vuln\"",
                    "xss",
                    "Pista hacia el Paso 6 (Final): Ahora actúa como Blue Team. Verifica que /api/files/download?filename=../confidential/flag.txt&mode=safe bloquee el escape con HTTP 403."
            ),
            new ChainStep(
                    6, "m1-blue", "PASO 6 // Contención Purple Team (Final)", "BLUE", 150,
                    "Valida la defensa canónica en mode=safe intentando acceder a ../confidential/flag.txt y captura la bandera de contención.",
                    "Por qué funciona: Path.normalize() resuelve los '../' y startsWith(baseDir) rechaza cualquier ruta fuera de /public/ con HTTP 403.",
                    List.of(
                            "Pista 1: Cambia el parámetro mode=vuln por mode=safe en /api/files/download.",
                            "Pista 2: Solicita ../confidential/flag.txt con mode=safe."
                    ),
                    "curl -i \"http://localhost:8080/api/files/download?filename=../confidential/flag.txt&mode=safe\"",
                    "file-safe",
                    "¡Misión Purple Team completada! Puedes sumar puntos extra con los retos restantes en /api/ctf/challenges."
            )
    );

    private static final List<Challenge> CHALLENGES = List.of(
            // MÓDULO 1 (DÍA 1): CWE-22 Path Traversal
            new Challenge(
                    "m1-red", 1, 1, "Módulo 1: Path Traversal", "CWE-22", "RED",
                    "Escape de Directorio POSIX",
                    "Utiliza secuencias relativas ../ para escapar de /public/ y leer /confidential/flag.txt.",
                    "Prueba solicitar ../confidential/flag.txt en el Validador de Certificados (modo Vulnerable).",
                    100, "FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}"
            ),
            new Challenge(
                    "m1-blue", 1, 1, "Módulo 1: Path Traversal", "CWE-22", "BLUE",
                    "Normalización Canónica y Frontera",
                    "Verifica que Path.normalize() + startsWith() bloquee el intento de escape devolviendo HTTP 403.",
                    "Cambia a modo Seguro y reintenta ../confidential/flag.txt.",
                    150, "FLAG{UNSL_CANONICAL_PATH_BOUNDARY_2026}"
            ),
            // MÓDULO 2 (DÍA 1 & 2): CWE-89 SQL Injection
            new Challenge(
                    "m2-red", 2, 1, "Módulo 2: SQL Injection", "CWE-89", "RED",
                    "Bypass de Autenticación SQLi (Parte 1)",
                    "Explota la concatenación SQL en /api/users/search para volcar toda la tabla de usuarios.",
                    "Inyecta ' OR '1'='1 en el buscador o login en modo Vulnerable.",
                    100, "FLAG{UNSL_SQLI_AUTH_BYPASS_2026}"
            ),
            new Challenge(
                    "m2-union", 2, 2, "Módulo 2: SQL Injection (Parte 2)", "CWE-89", "RED",
                    "Extracción UNION-Based (Esquema Secundario)",
                    "Usa UNION SELECT para consultar la tabla audit_secrets y extraer la bandera SQLI_UNION_CHALLENGE.",
                    "La consulta principal proyecta 5 columnas (id, username, password, role, ssn). Usa UNION SELECT sobre audit_secrets.",
                    150, "FLAG{UNSL_SQLI_UNION_EXTRACTION_2026}"
            ),
            new Challenge(
                    "m2-blue", 2, 2, "Módulo 2: SQL Injection", "CWE-89", "BLUE",
                    "Blindaje con PreparedStatement",
                    "Ejecuta la búsqueda en modo Seguro verificando que la inyección se trate como literal sin filtrar PII.",
                    "Cambia a modo Seguro y envía el payload SQLi para validar la defensa.",
                    150, "FLAG{UNSL_PREPARED_STATEMENT_DEFENDER_2026}"
            ),
            // MÓDULO 3 (DÍA 2): CWE-79 Cross-Site Scripting
            new Challenge(
                    "m3-red", 3, 2, "Módulo 3: Cross-Site Scripting (XSS)", "CWE-79", "RED",
                    "Inyección XSS Reflejada en el DOM",
                    "Inyecta una etiqueta HTML ejecutable en el saludo de perfil sin sanitización.",
                    "Envía <img src=x onerror=\"alert('XSS_UNSL')\"> en /api/profile/greet (modo Vulnerable).",
                    100, "FLAG{UNSL_XSS_DOM_INJECTION_ALERT_2026}"
            ),
            new Challenge(
                    "m3-stored", 3, 2, "Módulo 3: Cross-Site Scripting (XSS)", "CWE-79", "RED",
                    "XSS Almacenado Persistente en Servidor",
                    "Guarda un payload HTML/JS en el muro de Historia Académica que persista en BD.",
                    "Publica un payload con <img onerror=...> o <script> en Notas en Historia Académica (modo Vulnerable).",
                    150, "FLAG{UNSL_STORED_XSS_PERSISTENT_2026}"
            ),
            new Challenge(
                    "m3-blue", 3, 2, "Módulo 3: Cross-Site Scripting (XSS)", "CWE-79", "BLUE",
                    "Codificación Contextual y CSP",
                    "Activa el modo Seguro para aplicar Encode.forHtml() y verificar Content-Security-Policy.",
                    "Envía el payload XSS en modo Seguro y revisa la telemetría de cabeceras.",
                    150, "FLAG{UNSL_CSP_CONTEXTUAL_ENCODING_2026}"
            ),
            // DÍA 3: COMPETENCIA CTF
            new Challenge(
                    "ctf-backup", 4, 3, "Día 3: Competencia CTF", "CWE-22", "CTF",
                    "Respaldo Confidencial de Sala 8",
                    "Encuentra el archivo de respaldo interno ctf_day3_audit.txt oculto fuera del directorio público.",
                    "Aplica Path Traversal apuntando al directorio confidential/.",
                    200, "FLAG{UNSL_CTF_DAY3_HIDDEN_BACKUP_2026}"
            ),
            new Challenge(
                    "ctf-schema", 4, 3, "Día 3: Competencia CTF", "CWE-89", "CTF",
                    "Cazador de Esquemas (Top Secret)",
                    "Extrae la clave CTF_DAY3_DB_KEY almacenada en la tabla audit_secrets mediante SQLi.",
                    "Utiliza UNION SELECT sobre audit_secrets filtrando o listando todas las filas.",
                    250, "FLAG{UNSL_CTF_DAY3_SCHEMA_HUNTER_2026}"
            )
    );

    private static final Map<String, List<QuizQuestion>> QUIZZES = Map.of(
            "m1", List.of(
                    new QuizQuestion(
                            "m1-q1",
                            "¿Por qué falla una lista negra simple que solo elimina '../' una vez (replace(\"../\", \"\"))?",
                            List.of(
                                    "Porque el sistema operativo solo acepta rutas absolutas",
                                    "Porque secuencias anidadas como '....//' vuelven a formar '../' tras un único reemplazo",
                                    "Porque Java no soporta expresiones regulares en Strings"
                            ),
                            1,
                            "Un filtro de reemplazo único puede evadirse con '....//'. La defensa robusta normaliza primero la ruta canónica y valida startsWith(baseDir) o usa una lista blanca."
                    ),
                    new QuizQuestion(
                            "m1-q2",
                            "¿Cuál es la combinación estándar en Java NIO para contener Path Traversal (CWE-22)?",
                            List.of(
                                    "baseDir.resolve(input).normalize() seguido de targetPath.startsWith(baseDir)",
                                    "new File(baseDir, input).getName()",
                                    "Verificar únicamente que el nombre termine en .txt"
                            ),
                            0,
                            "Normalizar la ruta absoluta y verificar que comience estrictamente con el directorio base canónico impide cualquier escape."
                    )
            ),
            "m2", List.of(
                    new QuizQuestion(
                            "m2-q1",
                            "¿Por qué PreparedStatement neutraliza la inyección SQL (CWE-89)?",
                            List.of(
                                    "Porque escapa automáticamente las etiquetas HTML",
                                    "Porque separa el plano sintáctico de la consulta compilada de los datos enviados en placeholders '?'",
                                    "Porque cifra la base de datos en memoria"
                            ),
                            1,
                            "El motor SQL compila la estructura antes de recibir los valores; una comilla o un ' OR '1'='1 se evalúa como texto literal."
                    ),
                    new QuizQuestion(
                            "m2-q2",
                            "En una inyección UNION-Based, ¿qué condición debe cumplirse entre la consulta original y el SELECT inyectado?",
                            List.of(
                                    "Deben tener exactamente el mismo número de columnas y tipos compatibles",
                                    "Ambas consultas deben apuntar a la misma tabla",
                                    "El usuario de BD debe ser administrador"
                            ),
                            0,
                            "SQL exige igual cantidad de columnas y compatibilidad de tipos para unir dos conjuntos de resultados con UNION."
                    )
            ),
            "m3", List.of(
                    new QuizQuestion(
                            "m3-q1",
                            "¿Cuál es la diferencia principal entre XSS Reflejado y XSS Almacenado?",
                            List.of(
                                    "El XSS Reflejado solo afecta a servidores Linux",
                                    "El XSS Almacenado persiste en el servidor (BD/archivos) y afecta a cada usuario que cargue el recurso",
                                    "El XSS Almacenado no requiere navegador para ejecutarse"
                            ),
                            1,
                            "Al guardarse en BD o archivos del servidor, cualquier docente o alumno que consulte el perfil recibe el payload sin necesidad de un enlace manipulado."
                    ),
                    new QuizQuestion(
                            "m3-q2",
                            "¿Qué aporta la cabecera Content-Security-Policy (CSP) frente a XSS (CWE-79)?",
                            List.of(
                                    "Reemplaza la necesidad de escapar entradas en el backend",
                                    "Actúa como defensa en profundidad restringiendo qué scripts puede ejecutar el navegador",
                                    "Evita que el usuario envíe formularios POST"
                            ),
                            1,
                            "La defensa primaria es el escape contextual (Encode.forHtml / textContent) y CSP agrega una segunda barrera en el navegador."
                    )
            )
    );

    private final ClassroomStateService classroomState;
    private final String helpPassword;

    public CtfController(
            ClassroomStateService classroomState,
            @Value("${app.help.password:socosoco}") String helpPassword) {
        this.classroomState = classroomState;
        this.helpPassword = helpPassword;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> registerParticipant(@RequestBody Map<String, String> payload) {
        String sessionId = payload.get("sessionId");
        String alias = payload.get("alias");
        String workstation = payload.get("workstation");

        Participant p = classroomState.registerOrUpdateParticipant(sessionId, alias, workstation);
        log.info("[AULA] Participante registrado/actualizado: {} ({})", p.getAlias(), p.getWorkstation());

        return ResponseEntity.ok(Map.of(
                "sessionId", p.getSessionId(),
                "alias", p.getAlias(),
                "workstation", p.getWorkstation(),
                "points", p.getTotalPoints(),
                "solvedChallenges", p.getSolvedChallengeIds()
        ));
    }

    @GetMapping("/leaderboard")
    public ResponseEntity<Map<String, Object>> getLeaderboard() {
        if (!classroomState.isCtfUnlocked()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "locked", true,
                    "message", "La competencia CTF aún no ha sido liberada por el equipo docente."
            ));
        }
        List<Map<String, Object>> leaderboard = classroomState.getLeaderboard();
        return ResponseEntity.ok(Map.of(
                "totalParticipants", leaderboard.size(),
                "maxScore", CHALLENGES.stream().mapToInt(Challenge::points).sum(),
                "leaderboard", leaderboard
        ));
    }

    @GetMapping("/challenges")
    public ResponseEntity<Map<String, Object>> getChallenges() {
        if (!classroomState.isCtfUnlocked()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "locked", true,
                    "message", "Los desafíos CTF están ocultos hasta que el equipo docente los libere."
            ));
        }
        List<Map<String, Object>> publicChallenges = new ArrayList<>();
        int totalPoints = 0;

        for (Challenge c : CHALLENGES) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", c.id());
            item.put("moduleNumber", c.moduleNumber());
            item.put("dayNumber", c.dayNumber());
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

    @PostMapping("/submit")
    public ResponseEntity<Map<String, Object>> submitFlag(
            @RequestHeader(value = "X-Lab-Session", required = false) String headerSessionId,
            @RequestBody Map<String, String> payload) {

        if (!classroomState.isCtfUnlocked()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "valid", false,
                    "locked", true,
                    "message", "La competencia CTF aún no ha sido liberada por el equipo docente."
            ));
        }

        String submittedFlag = payload.getOrDefault("flag", "").trim();
        String sessionId = payload.getOrDefault("sessionId", headerSessionId != null ? headerSessionId : "");

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
            boolean newlyScored = true;
            if (sessionId != null && !sessionId.isBlank()) {
                Optional<Participant> p = classroomState.findParticipant(sessionId);
                if (p.isPresent()) {
                    newlyScored = p.get().recordSolve(c.id(), c.points());
                }
            }

            log.info("[CTF - VALIDACIÓN EXITOSA] Reto {} ({}) resuelto. +{} pts", c.id(), c.team(), c.points());

            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("valid", true);
            ok.put("newlyScored", newlyScored);
            ok.put("challengeId", c.id());
            ok.put("moduleNumber", c.moduleNumber());
            ok.put("dayNumber", c.dayNumber());
            ok.put("team", c.team());
            ok.put("title", c.title());
            ok.put("points", c.points());
            CHAIN_STEPS.stream()
                    .filter(s -> s.challengeId().equals(c.id()))
                    .findFirst()
                    .ifPresent(s -> {
                        ok.put("stepOrder", s.stepOrder());
                        ok.put("nextHint", s.nextHint());
                    });
            ok.put("message", "¡Bandera correcta! Reto '" + c.title() + "' completado (+" + c.points() + " pts).");
            return ResponseEntity.ok(ok);
        }

        log.warn("[CTF - BANDERA INVÁLIDA] Intento fallido: {}", submittedFlag);
        return ResponseEntity.badRequest().body(Map.of(
                "valid", false,
                "message", "Bandera incorrecta o no reconocida. Revisa la fase actual e intenta nuevamente."
        ));
    }

    @GetMapping("/chain")
    public ResponseEntity<Map<String, Object>> getCtfChain(
            @RequestParam(value = "sessionId", required = false) String sessionId,
            @RequestHeader(value = "X-Lab-Session", required = false) String headerSessionId) {

        if (!classroomState.isCtfUnlocked()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "locked", true,
                    "message", "La competencia CTF aún no ha sido liberada por el equipo docente."
            ));
        }

        String effectiveSession = (sessionId != null && !sessionId.isBlank()) ? sessionId : headerSessionId;
        Set<String> solved = effectiveSession != null
                ? classroomState.findParticipant(effectiveSession).map(Participant::getSolvedChallengeIds).orElse(Set.of())
                : Set.of();

        int activeOrder = CHAIN_STEPS.size() + 1;
        for (ChainStep s : CHAIN_STEPS) {
            if (!solved.contains(s.challengeId())) {
                activeOrder = s.stepOrder();
                break;
            }
        }

        List<Map<String, Object>> stepsPayload = new ArrayList<>();
        for (ChainStep s : CHAIN_STEPS) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("stepOrder", s.stepOrder());
            item.put("points", s.points());
            item.put("cwe", s.cwe());

            if (solved.contains(s.challengeId())) {
                item.put("status", "COMPLETED");
                item.put("challengeId", s.challengeId());
                item.put("title", s.title());
                item.put("didacticNote", s.didacticNote());
                item.put("nextHint", s.nextHint());
            } else if (s.stepOrder() == activeOrder) {
                item.put("status", "ACTIVE");
                item.put("challengeId", s.challengeId());
                item.put("title", s.title());
                item.put("briefing", s.briefing());
                item.put("didacticNote", s.didacticNote());
                item.put("conceptualHints", s.conceptualHints());
                item.put("suggestedCurl", s.suggestedCurl());
                item.put("endpointType", s.endpointType());
            } else {
                item.put("status", "LOCKED");
                item.put("title", "PASO " + s.stepOrder() + " // [BLOQUEADO - RESUELVE EL PASO " + (s.stepOrder() - 1) + "]");
            }
            stepsPayload.add(item);
        }

        return ResponseEntity.ok(Map.of(
                "totalSteps", CHAIN_STEPS.size(),
                "completedSteps", (int) CHAIN_STEPS.stream().filter(s -> solved.contains(s.challengeId())).count(),
                "activeStepOrder", Math.min(activeOrder, CHAIN_STEPS.size()),
                "steps", stepsPayload
        ));
    }

    @GetMapping("/quiz/{moduleId}")
    public ResponseEntity<Map<String, Object>> getQuiz(@PathVariable String moduleId) {
        List<QuizQuestion> questions = QUIZZES.get(moduleId);
        if (questions == null) {
            return ResponseEntity.notFound().build();
        }
        List<Map<String, Object>> sanitized = new ArrayList<>();
        for (QuizQuestion q : questions) {
            sanitized.add(Map.of(
                    "id", q.id(),
                    "prompt", q.prompt(),
                    "options", q.options()
            ));
        }
        return ResponseEntity.ok(Map.of("moduleId", moduleId, "questions", sanitized));
    }

    @PostMapping("/quiz/submit")
    public ResponseEntity<Map<String, Object>> submitQuiz(
            @RequestHeader(value = "X-Lab-Session", required = false) String headerSessionId,
            @RequestBody Map<String, Object> payload) {

        String moduleId = String.valueOf(payload.getOrDefault("moduleId", ""));
        List<QuizQuestion> questions = QUIZZES.get(moduleId);
        if (questions == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Módulo de cuestionario inválido."));
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> answers = (Map<String, Object>) payload.getOrDefault("answers", Map.of());
        int correctCount = 0;
        List<Map<String, Object>> feedback = new ArrayList<>();

        for (QuizQuestion q : questions) {
            int chosen = -1;
            if (answers.containsKey(q.id()) && answers.get(q.id()) != null) {
                try {
                    chosen = Integer.parseInt(String.valueOf(answers.get(q.id())));
                } catch (NumberFormatException ignored) {}
            }
            boolean isCorrect = chosen == q.correctIndex();
            if (isCorrect) correctCount++;

            feedback.add(Map.of(
                    "id", q.id(),
                    "correct", isCorrect,
                    "explanation", q.explanation()
            ));
        }

        boolean passed = correctCount == questions.size();
        String sessionId = payload.containsKey("sessionId")
                ? String.valueOf(payload.get("sessionId"))
                : headerSessionId;

        if (passed && sessionId != null && !sessionId.isBlank()) {
            classroomState.findParticipant(sessionId).ifPresent(p -> p.getPassedQuizzes().add(moduleId));
        }

        return ResponseEntity.ok(Map.of(
                "moduleId", moduleId,
                "passed", passed,
                "score", correctCount,
                "total", questions.size(),
                "feedback", feedback
        ));
    }

    @PostMapping("/unlock-help")
    public ResponseEntity<Map<String, Object>> unlockHelp(@RequestBody Map<String, String> payload) {
        String pwd = payload.getOrDefault("password", "");
        if (helpPassword.equals(pwd)) {
            return ResponseEntity.ok(Map.of("unlocked", true));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "unlocked", false,
                "message", "Sorry, try again. [AUTH_FAILED]"
        ));
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("labName", "Laboratorio de Ciberseguridad Web - UNSL");
        status.put("approach", "Purple Team Incremental (3 Jornadas)");
        status.put("totalChallenges", CHALLENGES.size());
        status.put("totalModules", 3);
        status.put("maxScore", CHALLENGES.stream().mapToInt(Challenge::points).sum());
        return ResponseEntity.ok(status);
    }
}
