package edu.unsl.ciberlab.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Inicializador de base de datos en memoria H2 y verificación de almacenamiento de archivos.
 * Precarga registros de prueba en la tabla 'users' y asegura la disponibilidad de directorios.
 */
@Component
public class DatabaseInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DatabaseInitializer.class);

    private final JdbcTemplate jdbcTemplate;

    @Value("${app.storage.base-dir:/app/storage}")
    private String storageBaseDir;

    public DatabaseInitializer(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(String... args) throws Exception {
        initializeDatabase();
        ensureStorageDirectories();
    }

    private void initializeDatabase() {
        log.info("[Purple Team] Inicializando esquema y registros en H2 in-memory...");

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

        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
        log.info("[Purple Team] Base de datos inicializada con {} registros en la tabla 'users'.", count);
    }

    private void ensureStorageDirectories() {
        // Determinamos la ruta base: si /app/storage no existe (entorno de pruebas local sin docker), usamos ./storage
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

            log.info("[Purple Team] Directorios y archivos de almacenamiento verificados en: {}", basePath.toAbsolutePath());
        } catch (IOException e) {
            log.error("[Purple Team] Error asegurando estructura de almacenamiento: {}", e.getMessage());
        }
    }
}
