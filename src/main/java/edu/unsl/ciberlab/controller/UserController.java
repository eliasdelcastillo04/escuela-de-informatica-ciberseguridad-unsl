package edu.unsl.ciberlab.controller;

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
 * MÓDULO 1: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command - 'SQL Injection')
 *
 * Enfoque Purple Team:
 * - Red Team: Demostrar cómo una entrada arbitraria altera el Árbol Sintáctico Abstracto (AST) del motor SQL.
 * - Blue Team: Refactorizar hacia consultas parametrizadas (PreparedStatement) y aplicar principio de menor privilegio.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    private final DataSource dataSource;

    public UserController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * Endpoint de búsqueda de usuarios.
     * Por defecto (mode="vuln" o no especificado) ejecuta la lógica vulnerable para el taller de auditoría.
     * Permite mode="safe" para demostraciones docentes en vivo de la remediación.
     */
    @GetMapping("/search")
    public ResponseEntity<Map<String, Object>> searchUsers(
            @RequestParam(name = "username", defaultValue = "") String username,
            @RequestParam(name = "mode", defaultValue = "vuln") String mode) {

        Map<String, Object> response = new HashMap<>();

        if ("safe".equalsIgnoreCase(mode)) {
            return ResponseEntity.ok(searchUsersRemediated(username));
        }

        // =========================================================================
        // [VULNERABLE DIDÁCTICO] CWE-89: Concatenación directa de entrada de usuario
        // =========================================================================
        // CAUSA RAÍZ: La variable 'username' se interpola directamente en el string SQL.
        // Si el atacante ingresa: ' OR '1'='1
        // La sentencia resultante es:
        // SELECT id, username, password, role, ssn FROM users WHERE username = '' OR '1'='1'
        // Esto cambia la semántica lógica de la condición booleana, devolviendo toda la tabla.
        // =========================================================================

        String sqlVulnerable = "SELECT id, username, password, role, ssn FROM users WHERE username = '" + username + "'";
        log.warn("[Purple Team - ALERTA CWE-89] Ejecutando consulta con concatenación directa: {}", sqlVulnerable);

        List<Map<String, Object>> userList = new ArrayList<>();
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sqlVulnerable)) {

            while (rs.next()) {
                Map<String, Object> user = new HashMap<>();
                user.put("id", rs.getInt("id"));
                user.put("username", rs.getString("username"));
                user.put("password", rs.getString("password")); // ¡Fuga de secreto por consulta amplia!
                user.put("role", rs.getString("role"));
                user.put("ssn", rs.getString("ssn"));           // ¡Fuga de PII (Social Security Number)!
                userList.add(user);
            }

            response.put("status", "SUCCESS");
            response.put("mode", "VULNERABLE (CWE-89)");
            response.put("securityAnalysis", "Inseguro: Concatenación directa en Statement. Vulnerable a inyección SQL de primer orden.");
            response.put("executedQuery", sqlVulnerable);
            response.put("rowCount", userList.size());
            response.put("users", userList);
            if (userList.size() > 1) {
                response.put("redTeamFlag", "FLAG{UNSL_SQLI_AUTH_BYPASS_2026}");
            }

            return ResponseEntity.ok(response);

        } catch (SQLException e) {
            log.error("[Purple Team] Error SQL durante ejecución vulnerable: {}", e.getMessage());
            response.put("status", "SQL_ERROR");
            response.put("mode", "VULNERABLE (CWE-89)");
            response.put("executedQuery", sqlVulnerable);
            response.put("errorMessage", e.getMessage());
            response.put("securityAnalysis", "El motor de base de datos arrojó un error de sintaxis SQL. En un entorno real, esto ayuda a un atacante en SQLi basado en errores.");
            return ResponseEntity.badRequest().body(response);
        }

        /*
         * =========================================================================
         * [GUÍA DE REMEDIACIÓN PARA EL ESTUDIANTE]
         * =========================================================================
         * Para corregir esta vulnerabilidad en el taller, reemplaza el bloque anterior por:
         *
         * String sqlSafe = "SELECT id, username, role FROM users WHERE username = ?";
         * try (Connection conn = dataSource.getConnection();
         *      PreparedStatement pstmt = conn.prepareStatement(sqlSafe)) {
         *     pstmt.setString(1, username);
         *     try (ResultSet rs = pstmt.executeQuery()) {
         *         while (rs.next()) {
         *             Map<String, Object> user = new HashMap<>();
         *             user.put("id", rs.getInt("id"));
         *             user.put("username", rs.getString("username"));
         *             user.put("role", rs.getString("role"));
         *             userList.add(user);
         *         }
         *     }
         * }
         * =========================================================================
         */
    }

    /**
     * Versión remediada: Aplica PreparedStatement (sentencia parametrizada)
     * y restringe la proyección de datos sensibles (mínimo privilegio de campos).
     */
    public Map<String, Object> searchUsersRemediated(String username) {
        Map<String, Object> response = new HashMap<>();
        List<Map<String, Object>> userList = new ArrayList<>();

        // 1. Separación de planos de control y datos mediante el placeholder '?'
        // 2. Mínimo privilegio: Se excluyen los campos 'password' y 'ssn' de la consulta
        String sqlRemediated = "SELECT id, username, role FROM users WHERE username = ?";
        log.info("[Purple Team - REMEDIADO] Ejecutando PreparedStatement parametrizado: {}", sqlRemediated);

        try (Connection conn = dataSource.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sqlRemediated)) {

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
            response.put("securityAnalysis", "Seguro: Uso de PreparedStatement. El driver SQL envía la consulta compilada y los parámetros como literales de datos aislados del plano sintáctico.");
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
