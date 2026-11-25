package edu.unsl.ciberlab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Pruebas automatizadas de seguridad (Purple Team) y aislamiento multi-estudiante.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CiberlabSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    // =========================================================================
    // MÓDULO 1 (DÍA 1): CWE-22 (Path Traversal + Sandbox Multi-Estudiante)
    // =========================================================================

    @Test
    @DisplayName("CWE-22 Red Team: Escape dentro de storage/ hacia ../confidential/flag.txt funciona en modo vuln")
    void testPathTraversalVulnerable() throws Exception {
        mockMvc.perform(get("/api/files/download")
                        .param("filename", "../confidential/flag.txt")
                        .param("mode", "vuln"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-PurpleTeam-Mode", containsString("VULNERABLE")))
                .andExpect(content().string(containsString("FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}")));
    }

    @Test
    @DisplayName("CWE-22 Sandbox: Intento de salir de storage/ (ej. /etc/passwd) bloqueado incluso en modo vuln")
    void testPathTraversalSandboxBoundary() throws Exception {
        mockMvc.perform(get("/api/files/download")
                        .param("filename", "../../../../etc/passwd")
                        .param("mode", "vuln"))
                .andExpect(status().isForbidden())
                .andExpect(content().string(containsString("SANDBOX")));
    }

    @Test
    @DisplayName("CWE-22 Blue Team: Bloqueo estricto con startsWith() devuelve 403 Forbidden")
    void testPathTraversalRemediated() throws Exception {
        mockMvc.perform(get("/api/files/download")
                        .param("filename", "../confidential/flag.txt")
                        .param("mode", "safe"))
                .andExpect(status().isForbidden())
                .andExpect(header().string("X-PurpleTeam-Access-Allowed", "false"))
                .andExpect(jsonPath("$.error").value("ACCESO DENEGADO (CWE-22)"));

        mockMvc.perform(get("/api/files/download")
                        .param("filename", "reporte_auditoria_2026.txt")
                        .param("mode", "safe"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-PurpleTeam-Access-Allowed", "true"))
                .andExpect(content().string(containsString("UNIVERSIDAD NACIONAL DE SAN LUIS")));
    }

    // =========================================================================
    // MÓDULO 2 (DÍA 1 & 2): CWE-89 (SQLi Parte 1, Parte 2 UNION/Blind y RO)
    // =========================================================================

    @Test
    @DisplayName("CWE-89 Red Team (Día 1): Auth Bypass booleano (' OR '1'='1)")
    void testSqlInjectionVulnerable() throws Exception {
        mockMvc.perform(get("/api/users/search")
                        .param("username", "' OR '1'='1")
                        .param("mode", "vuln")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.rowCount").value(greaterThanOrEqualTo(5)))
                .andExpect(jsonPath("$.users[0].password").exists())
                .andExpect(jsonPath("$.users[0].ssn").exists());
    }

    @Test
    @DisplayName("CWE-89 Red Team (Día 2): UNION-Based SQLi extrae secretos de audit_secrets y Blind SQLi responde booleano")
    void testSqlInjectionUnionAndBlind() throws Exception {
        mockMvc.perform(get("/api/users/search")
                        .param("username", "' UNION SELECT id, code_name, secret_value, classification, 'x' FROM audit_secrets--")
                        .param("mode", "vuln"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.unionFlag").value("FLAG{UNSL_SQLI_UNION_EXTRACTION_2026}"));

        mockMvc.perform(get("/api/users/check")
                        .param("username", "agomez' AND '1'='1")
                        .param("mode", "vuln"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(true));
    }

    @Test
    @DisplayName("CWE-89 Seguridad Multi-Estudiante: Usuario Read-Only bloquea DROP/DELETE y la tabla users sigue intacta")
    void testSqlInjectionReadOnlyIsolation() throws Exception {
        mockMvc.perform(get("/api/users/search")
                        .param("username", "'; DROP TABLE users; --")
                        .param("mode", "vuln"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("SQL_ERROR"));

        // Verificar que la tabla users sigue operativa para otros alumnos
        mockMvc.perform(get("/api/users/search")
                        .param("username", "agomez")
                        .param("mode", "safe"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rowCount").value(1));
    }

    @Test
    @DisplayName("CWE-89 Blue Team: PreparedStatement neutraliza inyección y protege PII")
    void testSqlInjectionRemediated() throws Exception {
        mockMvc.perform(get("/api/users/search")
                        .param("username", "' OR '1'='1")
                        .param("mode", "safe"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rowCount").value(0));

        mockMvc.perform(get("/api/users/search")
                        .param("username", "agomez")
                        .param("mode", "safe"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rowCount").value(1))
                .andExpect(jsonPath("$.users[0].password").doesNotExist())
                .andExpect(jsonPath("$.users[0].ssn").doesNotExist());
    }

    // =========================================================================
    // MÓDULO 3 (DÍA 2): CWE-79 (XSS Reflejado y Almacenado Aislado por Sesión)
    // =========================================================================

    @Test
    @DisplayName("CWE-79 Red Team y Blue Team: XSS Reflejado vs OWASP Encode.forHtml + CSP")
    void testReflectedXssVulnerableAndRemediated() throws Exception {
        String xssPayload = "<script>alert('XSS_UNSL')</script>";

        mockMvc.perform(get("/api/profile/greet")
                        .param("name", xssPayload)
                        .param("mode", "vuln"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Content-Security-Policy"))
                .andExpect(content().string(containsString("<script>alert('XSS_UNSL')</script>")));

        mockMvc.perform(get("/api/profile/greet")
                        .param("name", xssPayload)
                        .param("mode", "safe"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'none'")))
                .andExpect(content().string(not(containsString("<script>alert('XSS_UNSL')</script>"))))
                .andExpect(content().string(containsString("&lt;script&gt;alert(&#39;XSS_UNSL&#39;)&lt;/script&gt;")));
    }

    @Test
    @DisplayName("CWE-79 Aislamiento Multi-Estudiante: Notas Stored XSS aisladas por X-Lab-Session")
    void testStoredXssSessionIsolation() throws Exception {
        mockMvc.perform(post("/api/profile/notes")
                        .header("X-Lab-Session", "alumno-A")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"author\":\"Ana\",\"content\":\"<img src=x onerror=alert(1)>\",\"mode\":\"vuln\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.redTeamFlag").value("FLAG{UNSL_STORED_XSS_PERSISTENT_2026}"));

        mockMvc.perform(get("/api/profile/notes")
                        .header("X-Lab-Session", "alumno-B"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(0));
    }

    // =========================================================================
    // CTF, CUESTIONARIOS, RANKING Y PANEL DOCENTE
    // =========================================================================

    @Test
    @DisplayName("CTF & Ranking: Oculto hasta liberación docente; luego registro, envío de bandera, cuestionario y leaderboard")
    void testCtfLeaderboardAndQuiz() throws Exception {
        // Antes de liberar la CTF, los endpoints CTF deben responder 403 Forbidden
        mockMvc.perform(get("/api/ctf/challenges"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.locked").value(true));

        mockMvc.perform(get("/api/ctf/chain"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.locked").value(true));

        mockMvc.perform(get("/api/ctf/leaderboard"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.locked").value(true));

        // El docente libera la CTF
        mockMvc.perform(post("/api/docente/phase")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ctfUnlocked\":true,\"password\":\"unsl-docente-2026\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ctfUnlocked").value(true));

        mockMvc.perform(get("/api/ctf/challenges"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalChallenges").value(10))
                .andExpect(jsonPath("$.challenges[0].flag").doesNotExist());

        MvcResult reg = mockMvc.perform(post("/api/ctf/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"alias\":\"TestStudent\",\"workstation\":\"PC-11\"}"))
                .andExpect(status().isOk())
                .andReturn();

        String body = reg.getResponse().getContentAsString();
        String sessionId = body.replaceAll(".*\"sessionId\":\"([^\"]+)\".*", "$1");

        // Verificar cadena progresiva: Paso 1 ACTIVE, Paso 2 LOCKED
        mockMvc.perform(get("/api/ctf/chain").param("sessionId", sessionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.steps[0].status").value("ACTIVE"))
                .andExpect(jsonPath("$.steps[1].status").value("LOCKED"));

        // Resolver Paso 1 (m1-red) devuelve nextHint y desbloquea Paso 2
        mockMvc.perform(post("/api/ctf/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"flag\":\"FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}\",\"sessionId\":\"" + sessionId + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.nextHint").exists());

        mockMvc.perform(get("/api/ctf/chain").param("sessionId", sessionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.steps[0].status").value("COMPLETED"))
                .andExpect(jsonPath("$.steps[1].status").value("ACTIVE"));

        mockMvc.perform(post("/api/ctf/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"flag\":\"FLAG{UNSL_SQLI_AUTH_BYPASS_2026}\",\"sessionId\":\"" + sessionId + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.title").exists());

        mockMvc.perform(get("/api/ctf/leaderboard"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.leaderboard[0].alias").value("TestStudent"));

        mockMvc.perform(post("/api/ctf/quiz/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"moduleId\":\"m1\",\"sessionId\":\"" + sessionId + "\",\"answers\":{\"m1-q1\":1,\"m1-q2\":0}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(true));
    }

    @Test
    @DisplayName("Seguridad Aula: /h2-console deshabilitada y Panel Docente exige clave")
    void testH2DisabledAndDocenteAuth() throws Exception {
        mockMvc.perform(get("/h2-console"))
                .andExpect(status().is4xxClientError());

        mockMvc.perform(post("/api/docente/phase")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phase\":\"DIA_1\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/docente/phase")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phase\":\"DIA_2\",\"password\":\"unsl-docente-2026\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activePhase").value("DIA_2"));
    }
}
