package edu.unsl.ciberlab.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Inicializador de base de datos en memoria H2 y verificación de almacenamiento de archivos.
 * Configura tablas didácticas y un usuario H2 de solo lectura (ciberlab_ro) para aislar
 * los endpoints vulnerables de SQL Injection frente a mutaciones destructivas.
 */
@Component
public class DatabaseInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DatabaseInitializer.class);

    public static final String RO_DB_USER = "CIBERLAB_RO";
    public static final String RO_DB_PASS = "CiberLabReadOnly2026";

    private final JdbcTemplate jdbcTemplate;
    private final String datasourceUrl;

    @Value("${app.storage.base-dir:/app/storage}")
    private String storageBaseDir;

    public DatabaseInitializer(
            JdbcTemplate jdbcTemplate,
            @Value("${spring.datasource.url}") String datasourceUrl) {
        this.jdbcTemplate = jdbcTemplate;
        this.datasourceUrl = datasourceUrl;
    }

    @Override
    public void run(String... args) throws Exception {
        initializeDatabase();
        ensureStorageDirectories();
    }

    /**
     * Obtiene una conexión JDBC con privilegios exclusivos de lectura (SELECT)
     * sobre las tablas del taller SQLi, impidiendo DROP/DELETE/UPDATE/SHUTDOWN.
     */
    public Connection getReadOnlyConnection() throws SQLException {
        // Omitir parámetros de configuración global (;DB_CLOSE_DELAY=...) que requieren privilegios ADMIN en H2
        String roUrl = datasourceUrl.split(";")[0];
        return DriverManager.getConnection(roUrl, RO_DB_USER, RO_DB_PASS);
    }

    private void initializeDatabase() {
        log.info("[Purple Team] Inicializando esquema, registros y usuario Read-Only en H2...");

        jdbcTemplate.execute("DROP TABLE IF EXISTS users");
        jdbcTemplate.execute("""
            CREATE TABLE users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(100) NOT NULL UNIQUE,
                password VARCHAR(100) NOT NULL,
                role VARCHAR(50) NOT NULL,
                ssn VARCHAR(50) NOT NULL
            )
        """);

        jdbcTemplate.update("""
            INSERT INTO users (username, password, role, ssn) VALUES
            ('admin_sec', 'Admin2026!Sec#Key', 'ADMIN', '987-65-4321'),
            ('agomez', 'GomezPass#2026', 'STUDENT', '111-22-3333'),
            ('mrodriguez', 'Mrod@UNSL99', 'PROFESSOR', '444-55-6666'),
            ('clopez', 'LopezSecret77', 'RESEARCHER', '777-88-9999'),
            ('auditor_interno', 'Aud1t0r_SecOps!', 'AUDITOR', '333-44-5555')
        """);

        // Tabla secundaria para SQL Injection Parte 2 (UNION-Based & Schema Discovery)
        jdbcTemplate.execute("DROP TABLE IF EXISTS audit_secrets");
        jdbcTemplate.execute("""
            CREATE TABLE audit_secrets (
                id INT PRIMARY KEY AUTO_INCREMENT,
                code_name VARCHAR(100) NOT NULL,
                secret_value VARCHAR(255) NOT NULL,
                classification VARCHAR(50) NOT NULL
            )
        """);

        jdbcTemplate.update("""
            INSERT INTO audit_secrets (code_name, secret_value, classification) VALUES
            ('DB_BACKUP_TOKEN', 'BKP-UNSL-2026-9941', 'INTERNAL'),
            ('SQLI_UNION_CHALLENGE', 'FLAG{UNSL_SQLI_UNION_EXTRACTION_2026}', 'CONFIDENTIAL'),
            ('CTF_DAY3_DB_KEY', 'FLAG{UNSL_CTF_DAY3_SCHEMA_HUNTER_2026}', 'TOP_SECRET')
        """);

        // Tabla para XSS Almacenado persistente en servidor, aislado por session_id del alumno
        jdbcTemplate.execute("DROP TABLE IF EXISTS profile_notes");
        jdbcTemplate.execute("""
            CREATE TABLE profile_notes (
                id INT PRIMARY KEY AUTO_INCREMENT,
                session_id VARCHAR(80) NOT NULL,
                author VARCHAR(80) NOT NULL,
                content VARCHAR(600) NOT NULL,
                created_at VARCHAR(40) NOT NULL
            )
        """);

        // Usuario de solo lectura para ejecutar consultas SQLi vulnerables sin riesgo de destrucción
        jdbcTemplate.execute("DROP USER IF EXISTS " + RO_DB_USER);
        jdbcTemplate.execute("CREATE USER " + RO_DB_USER + " PASSWORD '" + RO_DB_PASS + "'");
        jdbcTemplate.execute("GRANT SELECT ON users TO " + RO_DB_USER);
        jdbcTemplate.execute("GRANT SELECT ON audit_secrets TO " + RO_DB_USER);

        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
        log.info("[Purple Team] BD inicializada: {} usuarios, 3 registros en audit_secrets, usuario RO listo.", count);
    }

    private void ensureStorageDirectories() {
        Path basePath = Paths.get(storageBaseDir);
        if (!Files.exists(basePath)) {
            basePath = Paths.get("./storage");
        }

        Path publicDir = basePath.resolve("public");
        Path confidentialDir = basePath.resolve("confidential");

        try {
            Files.createDirectories(publicDir);
            Files.createDirectories(confidentialDir);

            Path sampleReport = publicDir.resolve("reporte_auditoria_2026.txt");
            if (!Files.exists(sampleReport)) {
                Files.writeString(sampleReport, """
                    ==============================================================
                    UNIVERSIDAD NACIONAL DE SAN LUIS - REPORTE DE AUDITORÍA 2026
                    ==============================================================
                    Fecha: 2026-11-03
                    Estado General: OPERATIVO CON OBSERVACIONES
                    Servidores Auditados: 12 nodos
                    Vulnerabilidades Críticas Detectadas: 3 (En proceso de remediación didáctica)
                    ==============================================================
                    """);
            }

            Path samplePolicy = publicDir.resolve("politica_seguridad.txt");
            if (!Files.exists(samplePolicy)) {
                Files.writeString(samplePolicy, """
                    ==============================================================
                    POLÍTICA DE SEGURIDAD DE LA INFORMACIÓN - LABORATORIO WEB
                    ==============================================================
                    1. Separación de planos de control y datos en consultas SQL.
                    2. Codificación contextual para mitigar XSS.
                    3. Validación canónica de rutas con startsWith().
                    ==============================================================
                    """);
            }

            Path confidentialFlag = confidentialDir.resolve("flag.txt");
            if (!Files.exists(confidentialFlag)) {
                Files.writeString(confidentialFlag, """
                    FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}
                    [CONFIDENCIAL] Acceso no autorizado a registros sensibles de la Universidad.
                    CWE-22 explotado con éxito. Remediación requerida en FileController.java.
                    """);
            }

            Path ctfBackup = confidentialDir.resolve("ctf_day3_audit.txt");
            if (!Files.exists(ctfBackup)) {
                Files.writeString(ctfBackup, """
                    [RESPALDO INTERNO - DÍA 3 CTF]
                    Nodo: sala8-pc11.unsl.edu.ar
                    Evidencia de auditoría: FLAG{UNSL_CTF_DAY3_HIDDEN_BACKUP_2026}
                    Nota: Verificar que Path.normalize() + startsWith() bloquee este acceso.
                    """);
            }

            log.info("[Purple Team] Almacenamiento verificado en: {}", basePath.toAbsolutePath());
        } catch (IOException e) {
            log.error("[Purple Team] Error asegurando almacenamiento: {}", e.getMessage());
        }
    }
}
