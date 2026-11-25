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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MÓDULO 1 (DÍA 1): CWE-22 (Path Traversal)
 * - Red Team: Escape de /public/ hacia /confidential/ usando secuencias ../
 * - Sandbox Multi-Estudiante: Incluso en modo vulnerable, confina la lectura a storage/ (≤ 64 KB)
 *   para proteger el servidor compartido de la Sala de Máquinas.
 * - Blue Team: Normalización canónica con Path.normalize() y validación estricta startsWith(baseDir).
 */
@RestController
@RequestMapping("/api/files")
public class FileController {

    private static final Logger log = LoggerFactory.getLogger(FileController.class);
    private static final long MAX_FILE_SIZE_BYTES = 65_536L; // 64 KB límite seguro en aula

    @Value("${app.storage.base-dir:/app/storage}")
    private String configuredBaseDir;

    private Path getStorageRoot() {
        Path path = Paths.get(configuredBaseDir);
        if (Files.exists(path)) {
            return path.toAbsolutePath().normalize();
        }
        return Paths.get("./storage").toAbsolutePath().normalize();
    }

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

        Path storageRoot = getStorageRoot();
        Path publicRoot = storageRoot.resolve("public").normalize();
        Path targetPath = publicRoot.resolve(filename).normalize();

        // Confinamiento de seguridad multi-estudiante: permite escapar de /public/ hacia /confidential/
        // para demostrar CWE-22, pero bloquea salir de storage/ hacia archivos del sistema operativo.
        if (!targetPath.startsWith(storageRoot)) {
            log.warn("[Sandbox CWE-22] Intento de salida fuera de storage/ bloqueado: {}", filename);
            HttpHeaders sandboxHeaders = new HttpHeaders();
            sandboxHeaders.set("X-PurpleTeam-Mode", "VULNERABLE (Sandbox Boundary)");
            sandboxHeaders.set("X-PurpleTeam-Resolved-Path", targetPath.toString());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .headers(sandboxHeaders)
                    .body("LÍMITE DE SANDBOX (Aula Compartida): El modo vulnerable permite escapar de /public/ hacia /confidential/ (ej. ../confidential/flag.txt), pero bloquea salir del directorio del laboratorio.");
        }

        log.warn("[Purple Team - ALERTA CWE-22] Acceso en modo vulnerable a ruta: {}", targetPath);

        if (!Files.exists(targetPath) || !Files.isRegularFile(targetPath)) {
            HttpHeaders notFoundHeaders = new HttpHeaders();
            notFoundHeaders.set("X-PurpleTeam-Mode", "VULNERABLE (CWE-22)");
            notFoundHeaders.set("X-PurpleTeam-Resolved-Path", targetPath.toString());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .headers(notFoundHeaders)
                    .body("Archivo no encontrado: " + filename + " (Ruta buscada: " + targetPath + ")");
        }

        try {
            if (Files.size(targetPath) > MAX_FILE_SIZE_BYTES) {
                return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                        .body("Archivo excede el límite permitido de 64 KB.");
            }

            byte[] fileBytes = Files.readAllBytes(targetPath);
            Resource resource = new ByteArrayResource(fileBytes);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            headers.setContentDispositionFormData("attachment", targetPath.getFileName().toString());
            headers.set("X-PurpleTeam-Mode", "VULNERABLE (CWE-22)");
            headers.set("X-PurpleTeam-Base-Dir", publicRoot.toString());
            headers.set("X-PurpleTeam-Resolved-Path", targetPath.toString());
            headers.set("X-PurpleTeam-Traversal-Success", String.valueOf(!targetPath.startsWith(publicRoot)));

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(resource);

        } catch (IOException e) {
            log.error("[Purple Team] Error leyendo archivo: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al leer el archivo solicitado: " + e.getMessage());
        }
    }

    public ResponseEntity<?> downloadFileRemediated(String filename) {
        log.info("[Purple Team - REMEDIADO] Verificando ruta canónica con Path.normalize() y startsWith()");

        Path baseDir = getStorageRoot().resolve("public").toAbsolutePath().normalize();
        Path targetPath = baseDir.resolve(filename).normalize();

        if (!targetPath.startsWith(baseDir)) {
            log.warn("[Purple Team - BLOQUEO CWE-22] Path Traversal bloqueado. Base: {} | Destino: {}", baseDir, targetPath);

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

        if (!Files.exists(targetPath) || !Files.isRegularFile(targetPath)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Archivo no encontrado dentro del directorio público: " + filename);
        }

        try {
            if (Files.size(targetPath) > MAX_FILE_SIZE_BYTES) {
                return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                        .body("Archivo excede el límite permitido de 64 KB.");
            }

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
