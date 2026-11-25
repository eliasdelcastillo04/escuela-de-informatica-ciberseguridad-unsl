package edu.unsl.ciberlab.controller;

import edu.unsl.ciberlab.config.DatabaseInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MÓDULO 2 (DÍA 1 & DÍA 2): CWE-89 (SQL Injection)
 * - Día 1 (Parte 1): Auth Bypass booleano (' OR '1'='1) en /api/users/search.
 * - Día 2 (Parte 2): Extracción UNION-Based (tabla audit_secrets / esquemas) y Blind SQLi (/api/users/check).
 * - Aislamiento Multi-Estudiante: Los endpoints vulnerables usan el usuario Read-Only (CIBERLAB_RO)
 *   con queryTimeout de 2s, impidiendo DROP/DELETE/UPDATE/SHUTDOWN en la BD compartida.
 * - Blue Team: PreparedStatement y proyección mínima de columnas.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private static final int MAX_INPUT_LEN = 250;
    private static final int QUERY_TIMEOUT_SECONDS = 2;

    private final DataSource dataSource;
    private final DatabaseInitializer databaseInitializer;

    public UserController(DataSource dataSource, DatabaseInitializer databaseInitializer) {
        this.dataSource = dataSource;
        this.databaseInitializer = databaseInitializer;
    }

    @GetMapping("/search")
    public ResponseEntity<Map<String, Object>> searchUsers(
            @RequestParam(name = "username", defaultValue = "") String username,
            @RequestParam(name = "mode", defaultValue = "vuln") String mode) {

        if (username.length() > MAX_INPUT_LEN) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "INPUT_TOO_LONG",
                    "message", "La entrada excede el límite de " + MAX_INPUT_LEN + " caracteres."
            ));
        }

        if ("safe".equalsIgnoreCase(mode)) {
            return ResponseEntity.ok(searchUsersRemediated(username));
        }

        Map<String, Object> response = new HashMap<>();
        String sqlVulnerable = "SELECT id, username, password, role, ssn FROM users WHERE username = '" + username + "'";
        log.warn("[Purple Team - ALERTA CWE-89] Ejecutando consulta vulnerable (RO): {}", sqlVulnerable);

        List<Map<String, Object>> userList = new ArrayList<>();
        try (Connection conn = databaseInitializer.getReadOnlyConnection();
             Statement stmt = conn.createStatement()) {

            stmt.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
            try (ResultSet rs = stmt.executeQuery(sqlVulnerable)) {
                while (rs.next()) {
                    Map<String, Object> user = new HashMap<>();
                    user.put("id", rs.getObject(1));
                    user.put("username", rs.getString(2));
                    user.put("password", rs.getString(3));
                    user.put("role", rs.getString(4));
                    user.put("ssn", rs.getString(5));
                    userList.add(user);
                }
            }

            response.put("status", "SUCCESS");
            response.put("mode", "VULNERABLE (CWE-89)");
            response.put("securityAnalysis", "Inseguro: Concatenación directa en Statement (ejecutado con usuario H2 de solo lectura para proteger el aula).");
            response.put("executedQuery", sqlVulnerable);
            response.put("rowCount", userList.size());
            response.put("users", userList);
            if (userList.size() > 1) {
                response.put("redTeamFlag", "FLAG{UNSL_SQLI_AUTH_BYPASS_2026}");
            }

            boolean extractedUnionSecret = userList.stream().anyMatch(u ->
                    String.valueOf(u.get("password")).contains("FLAG{UNSL_SQLI_UNION_EXTRACTION_2026}")
                    || String.valueOf(u.get("ssn")).contains("FLAG{UNSL_SQLI_UNION_EXTRACTION_2026}")
                    || String.valueOf(u.get("username")).contains("FLAG{UNSL_SQLI_UNION_EXTRACTION_2026}"));
            if (extractedUnionSecret) {
                response.put("unionFlag", "FLAG{UNSL_SQLI_UNION_EXTRACTION_2026}");
            }

            return ResponseEntity.ok(response);

        } catch (SQLException e) {
            log.warn("[Purple Team] Error SQL durante ejecución vulnerable: {}", e.getMessage());
            response.put("status", "SQL_ERROR");
            response.put("mode", "VULNERABLE (CWE-89)");
            response.put("executedQuery", sqlVulnerable);
            response.put("errorMessage", e.getMessage());
            response.put("securityAnalysis", "El motor SQL rechazó la consulta (error de sintaxis, columnas distintas en UNION, o comando bloqueado por privilegios de solo lectura).");
            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * Día 2 (Módulo 1): Endpoint para practicar Blind SQL Injection (Boolean-Based).
     * Solo retorna true/false indicando si existe coincidencia, sin volcar filas.
     */
    @GetMapping("/check")
    public ResponseEntity<Map<String, Object>> checkUserExists(
            @RequestParam(name = "username", defaultValue = "") String username,
            @RequestParam(name = "mode", defaultValue = "vuln") String mode) {

        if (username.length() > MAX_INPUT_LEN) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "INPUT_TOO_LONG",
                    "message", "La entrada excede el límite de " + MAX_INPUT_LEN + " caracteres."
            ));
        }

        if ("safe".equalsIgnoreCase(mode)) {
            Map<String, Object> safeResp = new HashMap<>();
            String sqlSafe = "SELECT COUNT(*) FROM users WHERE username = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement pstmt = conn.prepareStatement(sqlSafe)) {
                pstmt.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
                pstmt.setString(1, username);
                try (ResultSet rs = pstmt.executeQuery()) {
                    rs.next();
                    int count = rs.getInt(1);
                    safeResp.put("status", "SUCCESS");
                    safeResp.put("mode", "REMEDIATED (PreparedStatement)");
                    safeResp.put("exists", count > 0);
                    safeResp.put("blueTeamFlag", "FLAG{UNSL_PREPARED_STATEMENT_DEFENDER_2026}");
                    return ResponseEntity.ok(safeResp);
                }
            } catch (SQLException e) {
                safeResp.put("status", "ERROR");
                safeResp.put("errorMessage", e.getMessage());
                return ResponseEntity.internalServerError().body(safeResp);
            }
        }

        String sqlVuln = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'";
        Map<String, Object> resp = new HashMap<>();
        try (Connection conn = databaseInitializer.getReadOnlyConnection();
             Statement stmt = conn.createStatement()) {
            stmt.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
            try (ResultSet rs = stmt.executeQuery(sqlVuln)) {
                rs.next();
                int count = rs.getInt(1);
                boolean exists = count > 0;
                resp.put("status", "SUCCESS");
                resp.put("mode", "VULNERABLE (Blind SQLi)");
                resp.put("exists", exists);
                resp.put("executedQuery", sqlVuln);
                if (exists && username.contains("'")) {
                    resp.put("blindHint", "La condición booleana inyectada evaluó TRUE.");
                }
                return ResponseEntity.ok(resp);
            }
        } catch (SQLException e) {
            resp.put("status", "SQL_ERROR");
            resp.put("mode", "VULNERABLE (Blind SQLi)");
            resp.put("exists", false);
            resp.put("errorMessage", e.getMessage());
            return ResponseEntity.badRequest().body(resp);
        }
    }

    public Map<String, Object> searchUsersRemediated(String username) {
        Map<String, Object> response = new HashMap<>();
        List<Map<String, Object>> userList = new ArrayList<>();

        String sqlRemediated = "SELECT id, username, role FROM users WHERE username = ?";
        log.info("[Purple Team - REMEDIADO] Ejecutando PreparedStatement parametrizado: {}", sqlRemediated);

        try (Connection conn = dataSource.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlRemediated)) {

            pstmt.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
            pstmt.setString(1, username);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> user = new HashMap<>();
                    user.put("id", rs.getInt("id"));
                    user.put("username", rs.getString("username"));
                    user.put("role", rs.getString("role"));
                    userList.add(user);
                }
            }

            response.put("status", "SUCCESS");
            response.put("mode", "REMEDIATED (PreparedStatement)");
            response.put("securityAnalysis", "Seguro: Uso de PreparedStatement. El driver SQL envía la consulta compilada y los parámetros como literales aislados del plano sintáctico.");
            response.put("parameterBound", username);
            response.put("executedQuery", sqlRemediated + " [Param 1 = '" + username + "']");
            response.put("rowCount", userList.size());
            response.put("users", userList);
            response.put("blueTeamFlag", "FLAG{UNSL_PREPARED_STATEMENT_DEFENDER_2026}");

        } catch (SQLException e) {
            log.error("[Purple Team] Error SQL durante ejecución remediada: {}", e.getMessage());
            response.put("status", "ERROR");
            response.put("errorMessage", e.getMessage());
        }

        return response;
    }
}
