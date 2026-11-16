package edu.unsl.ciberlab.controller;

import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * MÓDULO 2: CWE-79 (Improper Neutralization of Input During Web Page Generation - 'Cross-Site Scripting')
 *
 * Enfoque Purple Team:
 * - Red Team: Inyección de payload script/HTML malicioso que se refleja en la respuesta y se ejecuta en el navegador.
 * - Blue Team: Sanitización contextual con OWASP Java Encoder (Encode.forHtml) y política de defensa en profundidad
 *   mediante cabeceras HTTP Content-Security-Policy (CSP).
 */
@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private static final Logger log = LoggerFactory.getLogger(ProfileController.class);

    /**
     * Endpoint de bienvenida de perfil de usuario.
     * Devuelve HTML directamente al navegador.
     *
     * @param name Nombre ingresado por el usuario.
     * @param mode Modo de ejecución ("vuln" por defecto, o "safe" para demostración docente).
     */
    @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> greetUser(
            @RequestParam(name = "name", defaultValue = "Invitado") String name,
            @RequestParam(name = "mode", defaultValue = "vuln") String mode) {

        if ("safe".equalsIgnoreCase(mode)) {
            return greetUserRemediated(name);
        }

        // =========================================================================
        // [VULNERABLE DIDÁCTICO] CWE-79: Reflejo directo de entrada en contexto HTML
        // =========================================================================
        // CAUSA RAÍZ: La variable 'name' se concatena en el cuerpo HTML sin codificación contextual.
        // Si el usuario envía: <script>alert('XSS')</script> o <img src=x onerror=alert(1)>
        // El navegador del usuario final parsea la cadena como etiquetas ejecutables en el DOM.
        // Adicionalmente, NO se define cabecera Content-Security-Policy (CSP), permitiendo
        // la ejecución indiscriminada de scripts inline.
        // =========================================================================

        log.warn("[Purple Team - ALERTA CWE-79] Reflejando entrada cruda sin sanitizar: {}", name);

        String htmlVulnerable = """
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <title>Portal Universitario - Saludo de Perfil</title>
                <style>
                    body { font-family: system-ui, sans-serif; padding: 1.5rem; background: #fff; color: #111; }
                    .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 1.25rem; max-width: 600px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                    .badge-vuln { background: #fee2e2; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }
                    .telemetry { margin-top: 1rem; font-family: monospace; font-size: 0.85rem; background: #f3f4f6; padding: 0.75rem; border-radius: 4px; }
                </style>
            </head>
            <body>
                <div class="card">
                    <span class="badge-vuln">ESTADO: MODO VULNERABLE (CWE-79)</span>
                    <h2>¡Bienvenido/a a la plataforma, %s!</h2>
                    <p>Tu sesión de entrenamiento Purple Team está actualmente activa.</p>
                    <div class="telemetry">
                        <strong>Telemetría HTTP Servidor:</strong><br>
                        Entrada recibida: %s<br>
                        Cabecera Content-Security-Policy: [NO ESTABLECIDA]<br>
                        Escape contextual: NINGUNO
                    </div>
                </div>
            </body>
            </html>
            """.formatted(name, name);

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-PurpleTeam-Mode", "VULNERABLE (CWE-79)");
        headers.set("X-PurpleTeam-Sanitization", "NONE");
        headers.set("X-PurpleTeam-CSP", "ABSENT");
        String lowerName = name.toLowerCase();
        if (lowerName.contains("<script") || lowerName.contains("onerror") || lowerName.contains("onload") || lowerName.contains("<svg") || lowerName.contains("<img")) {
            headers.set("X-PurpleTeam-Red-Flag", "FLAG{UNSL_XSS_DOM_INJECTION_ALERT_2026}");
        }

        return ResponseEntity.ok()
                .headers(headers)
                .body(htmlVulnerable);

        /*
         * =========================================================================
         * [GUÍA DE REMEDIACIÓN PARA EL ESTUDIANTE]
         * =========================================================================
         * Para corregir esta vulnerabilidad:
         * 1. Codifica la variable antes de inyectarla usando OWASP Encoder:
         *    String safeName = Encode.forHtml(name);
         *
         * 2. Configura cabeceras defensivas estrictas (Content-Security-Policy):
         *    HttpHeaders safeHeaders = new HttpHeaders();
         *    safeHeaders.set("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none';");
         *    safeHeaders.set("X-Content-Type-Options", "nosniff");
         *
         * 3. Retorna la respuesta con el safeName y las safeHeaders.
         * =========================================================================
         */
    }

    /**
     * Versión remediada: Aplica Encode.forHtml() de OWASP Java Encoder
     * y restringe la política de ejecución del navegador mediante Content-Security-Policy.
     */
    public ResponseEntity<String> greetUserRemediated(String name) {
        log.info("[Purple Team - REMEDIADO] Aplicando sanitización contextual Encode.forHtml() y cabeceras CSP");

        // 1. Sanitización contextual con OWASP Encoder: convierte <, >, ", ', & a sus entidades HTML seguras
        String safeName = Encode.forHtml(name);

        String htmlRemediated = """
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <title>Portal Universitario - Saludo de Perfil (Seguro)</title>
                <style>
                    body { font-family: system-ui, sans-serif; padding: 1.5rem; background: #fff; color: #111; }
                    .card { border: 1px solid #bbf7d0; border-radius: 8px; padding: 1.25rem; max-width: 600px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                    .badge-safe { background: #dcfce7; color: #166534; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }
                    .telemetry { margin-top: 1rem; font-family: monospace; font-size: 0.85rem; background: #f0fdf4; padding: 0.75rem; border-radius: 4px; border: 1px solid #bbf7d0; }
                </style>
            </head>
            <body>
                <div class="card">
                    <span class="badge-safe">ESTADO: REMEDIADO (Encode.forHtml + CSP)</span>
                    <h2>¡Bienvenido/a a la plataforma, %s!</h2>
                    <p>Tu saludo ha sido sanitizado contextualmente contra inyecciones XSS.</p>
                    <div class="telemetry">
                        <strong>Telemetría Defensiva Aplicada:</strong><br>
                        Entrada original: %s<br>
                        Entidad HTML codificada: %s<br>
                        Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none';<br>
                        X-Content-Type-Options: nosniff
                    </div>
                </div>
            </body>
            </html>
            """.formatted(safeName, Encode.forHtmlContent(name), safeName);

        // 2. Cabeceras HTTP defensivas
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-PurpleTeam-Mode", "REMEDIATED (CWE-79 Mitigated)");
        headers.set("X-PurpleTeam-Sanitization", "OWASP Encode.forHtml");
        headers.set("X-PurpleTeam-CSP", "default-src 'self'; script-src 'none'; object-src 'none'");
        headers.set("X-PurpleTeam-Blue-Flag", "FLAG{UNSL_CSP_CONTEXTUAL_ENCODING_2026}");

        return ResponseEntity.ok()
                .headers(headers)
                .body(htmlRemediated);
    }
}
