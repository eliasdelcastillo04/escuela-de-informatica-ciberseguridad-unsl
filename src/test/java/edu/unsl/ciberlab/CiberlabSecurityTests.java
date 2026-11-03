package edu.unsl.ciberlab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Pruebas automatizadas de seguridad (Purple Team) para validar tanto la reproducibilidad didáctica
 * de las fallas (Red Team) como la efectividad de las remediaciones (Blue Team).
 */
@SpringBootTest
@AutoConfigureMockMvc
class CiberlabSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    // =========================================================================
    // TESTS MÓDULO 1: CWE-89 (SQL Injection)
    // =========================================================================

    @Test
    @DisplayName("CWE-89 Red Team: Inyección SQL exitosa mediante bypass booleano (' OR '1'='1)")
    void testSqlInjectionVulnerable() throws Exception {
        mockMvc.perform(get("/api/users/search")
                        .param("username", "' OR '1'='1")
                        .param("mode", "vuln")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.mode").value("VULNERABLE (CWE-89)"))
                .andExpect(jsonPath("$.rowCount").value(greaterThanOrEqualTo(5)))
                // Verifica la fuga de credenciales y SSN
                .andExpect(jsonPath("$.users[0].password").exists())
                .andExpect(jsonPath("$.users[0].ssn").exists())
                .andExpect(jsonPath("$.executedQuery").value(containsString("' OR '1'='1")));
    }

    @Test
    @DisplayName("CWE-89 Blue Team: PreparedStatement neutraliza la inyección y previene fuga de PII")
    void testSqlInjectionRemediated() throws Exception {
        mockMvc.perform(get("/api/users/search")
                        .param("username", "' OR '1'='1")
                        .param("mode", "safe")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.mode").value("REMEDIATED (PreparedStatement)"))
                // Al ser parametrizado, busca literalmente el username "' OR '1'='1", que no existe
                .andExpect(jsonPath("$.rowCount").value(0))
                .andExpect(jsonPath("$.users").isEmpty());

        // Búsqueda legítima en modo seguro
        mockMvc.perform(get("/api/users/search")
                        .param("username", "agomez")
                        .param("mode", "safe")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rowCount").value(1))
                .andExpect(jsonPath("$.users[0].username").value("agomez"))
                // Principio de mínimo privilegio: password y ssn no deben existir en el DTO seguro
                .andExpect(jsonPath("$.users[0].password").doesNotExist())
                .andExpect(jsonPath("$.users[0].ssn").doesNotExist());
    }

    // =========================================================================
    // TESTS MÓDULO 2: CWE-79 (Reflected XSS)
    // =========================================================================

    @Test
    @DisplayName("CWE-79 Red Team: Reflejo crudo de script sin codificación contextual ni CSP")
    void testReflectedXssVulnerable() throws Exception {
        String xssPayload = "<script>alert('XSS_UNSL')</script>";

        mockMvc.perform(get("/api/profile/greet")
                        .param("name", xssPayload)
                        .param("mode", "vuln"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(header().string("X-PurpleTeam-Mode", containsString("VULNERABLE")))
                .andExpect(header().doesNotExist("Content-Security-Policy"))
                // La etiqueta se refleja textualmente sin escapar
                .andExpect(content().string(containsString("<script>alert('XSS_UNSL')</script>")));
    }

    @Test
    @DisplayName("CWE-79 Blue Team: Encode.forHtml() sanitiza la entrada y se aplica Content-Security-Policy")
    void testReflectedXssRemediated() throws Exception {
        String xssPayload = "<script>alert('XSS_UNSL')</script>";

        mockMvc.perform(get("/api/profile/greet")
                        .param("name", xssPayload)
                        .param("mode", "safe"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(header().string("X-PurpleTeam-Mode", containsString("REMEDIATED")))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'none'")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                // El script no debe aparecer sin escapar en la salida HTML
                .andExpect(content().string(not(containsString("<script>alert('XSS_UNSL')</script>"))))
                .andExpect(content().string(containsString("&lt;script&gt;alert(&#39;XSS_UNSL&#39;)&lt;/script&gt;")));
    }

    // =========================================================================
    // TESTS MÓDULO 3: CWE-22 (Path Traversal)
    // =========================================================================

    @Test
    @DisplayName("CWE-22 Red Team: Escape de directorio con ../confidential/flag.txt exitoso en modo vulnerable")
    void testPathTraversalVulnerable() throws Exception {
        mockMvc.perform(get("/api/files/download")
                        .param("filename", "../confidential/flag.txt")
                        .param("mode", "vuln"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-PurpleTeam-Mode", containsString("VULNERABLE")))
                .andExpect(content().string(containsString("FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}")));
    }

    @Test
    @DisplayName("CWE-22 Blue Team: Bloqueo estricto con startsWith() devuelve 403 Forbidden")
    void testPathTraversalRemediated() throws Exception {
        // Intento de Path Traversal bloqueado
        mockMvc.perform(get("/api/files/download")
                        .param("filename", "../confidential/flag.txt")
                        .param("mode", "safe"))
                .andExpect(status().isForbidden())
                .andExpect(header().string("X-PurpleTeam-Access-Allowed", "false"))
                .andExpect(jsonPath("$.error").value("ACCESO DENEGADO (CWE-22)"));

        // Descarga legítima de archivo público permitida en modo seguro
        mockMvc.perform(get("/api/files/download")
                        .param("filename", "reporte_auditoria_2026.txt")
                        .param("mode", "safe"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-PurpleTeam-Access-Allowed", "true"))
                .andExpect(content().string(containsString("UNIVERSIDAD NACIONAL DE SAN LUIS")));
    }
}
