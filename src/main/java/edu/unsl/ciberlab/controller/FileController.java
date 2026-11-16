package edu.unsl.ciberlab.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MÓDULO 3: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory - 'Path Traversal')
 *
 * Enfoque Purple Team:
 * - Red Team: Inyección de secuencias dot-dot-slash (../) para escapar del directorio público /public/
 *   y acceder a archivos restringidos en /confidential/ (e.g. flag.txt).
 * - Blue Team: Normalización canónica de rutas con java.nio.file.Path y verificación estricta de límites
 *   mediante targetPath.startsWith(baseDirectory).
 */
@RestController
@RequestMapping("/api/files")
public class FileController {

    private static final Logger log = LoggerFactory.getLogger(FileController.class);

    @Value("${app.storage.base-dir:/app/storage}")
    private String configuredBaseDir;

    /**
     * Resuelve la ruta base activa (/app/storage en Docker o ./storage en local).
     */
    private Path getStorageRoot() {
        Path path = Paths.get(configuredBaseDir);
        if (Files.exists(path)) {
            return path.toAbsolutePath().normalize();
        }
        return Paths.get("./storage").toAbsolutePath().normalize();
    }

    /**
     * Endpoint para listar los archivos autorizados en el directorio público.
     */
    @GetMapping("/list")
    public ResponseEntity<Map<String, Object>> listPublicFiles() {
        Path publicDir = getStorageRoot().resolve("public").normalize();
        List<Map<String, Object>> files = new ArrayList<>();

        if (Files.exists(publicDir) && Files.isDirectory(publicDir)) {
            try (var stream = Files.list(publicDir)) {
                stream.filter(Files::isRegularFile).forEach(p -> {
                    try {
                        Map<String, Object> fileInfo = new HashMap<>();
                        fileInfo.put("filename", p.getFileName().toString());
                        fileInfo.put("sizeBytes", Files.size(p));
                        fileInfo.put("category", "PUBLIC");
                        files.add(fileInfo);
                    } catch (IOException ignored) {}
                });
            } catch (IOException e) {
                log.error("[Purple Team] Error listando archivos públicos: {}", e.getMessage());
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("publicDirectory", publicDir.toString());
        response.put("files", files);
        response.put("totalFiles", files.size());
        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint de descarga de archivos.
     * Por defecto (mode="vuln") ejecuta la concatenación insegura que permite Path Traversal.
     * Con mode="safe" ejecuta la validación con java.nio.file.Path.
     */
    @GetMapping("/download")
    public ResponseEntity<?> downloadFile(
            @RequestParam(name = "filename", defaultValue = "") String filename,
            @RequestParam(name = "mode", defaultValue = "vuln") String mode) {

        if (filename == null || filename.isBlank()) {
            return ResponseEntity.badRequest().body("Debe especificar un parámetro 'filename'.");
        }

        if ("safe".equalsIgnoreCase(mode)) {
            return downloadFileRemediated(filename);
        }

        // =========================================================================
        // [VULNERABLE DIDÁCTICO] CWE-22: Concatenación directa de nombres de archivo
        // =========================================================================
        // CAUSA RAÍZ: new File(base, filename) concatena literalmente la ruta.
        // Si el atacante envía: ../confidential/flag.txt
        // El sistema operativo resuelve la ruta canónica fuera de 'public/', alcanzando 'confidential/'.
        // No existe validación canónica de prefijo (startsWith).
        // =========================================================================

        Path publicRoot = getStorageRoot().resolve("public");
        File targetFile = new File(publicRoot.toFile(), filename);

        log.warn("[Purple Team - ALERTA CWE-22] Intentando acceder a archivo mediante ruta vulnerable: {}", targetFile.getPath());

        if (!targetFile.exists() || !targetFile.isFile()) {
            HttpHeaders notFoundHeaders = new HttpHeaders();
            notFoundHeaders.set("X-PurpleTeam-Mode", "VULNERABLE (CWE-22)");
            notFoundHeaders.set("X-PurpleTeam-Resolved-Path", targetFile.getAbsolutePath());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .headers(notFoundHeaders)
                    .body("Archivo no encontrado: " + filename + " (Ruta buscada: " + targetFile.getAbsolutePath() + ")");
        }

        try {
            byte[] fileBytes = Files.readAllBytes(targetFile.toPath());
            Resource resource = new ByteArrayResource(fileBytes);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            headers.setContentDispositionFormData("attachment", targetFile.getName());
            headers.set("X-PurpleTeam-Mode", "VULNERABLE (CWE-22)");
            headers.set("X-PurpleTeam-Base-Dir", publicRoot.toAbsolutePath().toString());
            headers.set("X-PurpleTeam-Resolved-Path", targetFile.getAbsolutePath());
            headers.set("X-PurpleTeam-Traversal-Success", String.valueOf(!targetFile.getAbsolutePath().startsWith(publicRoot.toAbsolutePath().toString())));

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(resource);

        } catch (IOException e) {
            log.error("[Purple Team] Error leyendo archivo: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al leer el archivo solicitado: " + e.getMessage());
        }

        /*
         * =========================================================================
         * [GUÍA DE REMEDIACIÓN PARA EL ESTUDIANTE]
         * =========================================================================
         * Para corregir esta vulnerabilidad:
         * 1. Usa la API moderna java.nio.file.Path:
         *    Path baseDir = getStorageRoot().resolve("public").toAbsolutePath().normalize();
         *    Path targetPath = baseDir.resolve(filename).normalize();
         *
         * 2. Verifica canónicamente que la ruta resultante comience por el directorio base:
         *    if (!targetPath.startsWith(baseDir)) {
         *        // ¡Intento de escape de directorio detectado!
         *        return ResponseEntity.status(HttpStatus.FORBIDDEN)
         *            .body("ALERTA DE SEGURIDAD (CWE-22): Acceso fuera del directorio autorizado denegado.");
         *    }
         *
         * 3. Verifica que el archivo exista y sea regular:
         *    if (!Files.exists(targetPath) || !Files.isRegularFile(targetPath)) {
         *        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Archivo no encontrado.");
         *    }
         * =========================================================================
         */
    }

    /**
     * Versión remediada: Aplica java.nio.file.Path, normalize() y validación estricta startsWith().
     */
    public ResponseEntity<?> downloadFileRemediated(String filename) {
        log.info("[Purple Team - REMEDIADO] Verificando ruta canónica con java.nio.file.Path.normalize() y startsWith()");

        // 1. Obtener la ruta base canónica normalizada
        Path baseDir = getStorageRoot().resolve("public").toAbsolutePath().normalize();

        // 2. Resolver la ruta solicitada y normalizar (elimina secuencias ../ y ./)
        Path targetPath = baseDir.resolve(filename).normalize();

        // 3. Verificación estricta de pertenencia al directorio base (defensa contra Path Traversal)
        if (!targetPath.startsWith(baseDir)) {
            log.warn("[Purple Team - BLOQUEO CWE-22] Intento de Path Traversal bloqueado. Base: {} | Destino intentado: {}",
                    baseDir, targetPath);

            HttpHeaders blockedHeaders = new HttpHeaders();
            blockedHeaders.set("X-PurpleTeam-Mode", "REMEDIATED (CWE-22 Blocked)");
            blockedHeaders.set("X-PurpleTeam-Base-Dir", baseDir.toString());
            blockedHeaders.set("X-PurpleTeam-Resolved-Path", targetPath.toString());
            blockedHeaders.set("X-PurpleTeam-Access-Allowed", "false");
            blockedHeaders.set("X-PurpleTeam-Blue-Flag", "FLAG{UNSL_CANONICAL_PATH_BOUNDARY_2026}");

            Map<String, Object> errorPayload = new HashMap<>();
            errorPayload.put("error", "ACCESO DENEGADO (CWE-22)");
            errorPayload.put("securityReason", "La ruta resuelta ('" + targetPath + "') intenta salir del directorio base permitido ('" + baseDir + "').");
            errorPayload.put("remediationRule", "targetPath.startsWith(baseDirectory) == false -> HTTP 403 Forbidden");
            errorPayload.put("blueTeamFlag", "FLAG{UNSL_CANONICAL_PATH_BOUNDARY_2026}");

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .headers(blockedHeaders)
                    .body(errorPayload);
        }

        // 4. Verificación de existencia como archivo regular dentro del límite permitido
        if (!Files.exists(targetPath) || !Files.isRegularFile(targetPath)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Archivo no encontrado dentro del directorio público: " + filename);
        }

        try {
            byte[] fileBytes = Files.readAllBytes(targetPath);
            Resource resource = new ByteArrayResource(fileBytes);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            headers.setContentDispositionFormData("attachment", targetPath.getFileName().toString());
            headers.set("X-PurpleTeam-Mode", "REMEDIATED (CWE-22 Mitigated)");
            headers.set("X-PurpleTeam-Base-Dir", baseDir.toString());
            headers.set("X-PurpleTeam-Resolved-Path", targetPath.toString());
            headers.set("X-PurpleTeam-Access-Allowed", "true");

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(resource);

        } catch (IOException e) {
            log.error("[Purple Team] Error leyendo archivo seguro: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al leer archivo: " + e.getMessage());
        }
    }
}
