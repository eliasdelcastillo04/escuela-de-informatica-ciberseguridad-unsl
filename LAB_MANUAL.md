# Manual de Laboratorio: Seguridad en Aplicaciones Web
## Enfoque Purple Team: Detección, Telemetría y Remediación en Java (Spring Boot)
### Universidad Nacional de San Luis (UNSL)

---

## 1. Prerrequisitos e Inicialización del Entorno

### 1.1. Requisitos Previos en la Estación de Trabajo
Para completar este laboratorio, la máquina del estudiante debe contar con:
- **Docker Engine** (versión 20.10 o superior) y **Docker Compose v2**.
- (Opcional para desarrollo local sin Docker): **JDK 17** y **Apache Maven 3.8+**.
- Un navegador web moderno (Firefox, Chrome, Chromium o Edge).
- Un cliente HTTP de terminal como `curl` o terminal interactiva.

### 1.2. Estructura del Proyecto
```text
laboratorio-prueba/
├── Dockerfile                      # Empaquetamiento multi-stage sin privilegios
├── docker-compose.yml              # Despliegue con límites de CPU y RAM (512MB)
├── pom.xml                         # Dependencias Maven (Spring Boot 3.3.x, OWASP Encoder)
├── LAB_MANUAL.md                   # Este manual de ejercicios
├── storage/                        # Sistema de archivos local del laboratorio
│   ├── public/                     # Archivos públicos accesibles
│   │   ├── reporte_auditoria_2026.txt
│   │   └── politica_seguridad.txt
│   └── confidential/               # Directorio restringido
│       └── flag.txt                # Bandera de prueba para CWE-22
└── src/
    ├── main/
    │   ├── java/edu/unsl/ciberlab/
    │   │   ├── CiberlabApplication.java
    │   │   ├── config/DatabaseInitializer.java
    │   │   └── controller/
    │   │       ├── UserController.java      # Módulo 1 (CWE-89 SQLi)
    │   │       ├── ProfileController.java   # Módulo 2 (CWE-79 XSS)
    │   │       └── FileController.java      # Módulo 3 (CWE-22 Path Traversal)
    │   └── resources/
    │       ├── application.properties
    │       └── static/index.html            # Interfaz interactiva Purple Team
    └── test/java/edu/unsl/ciberlab/
        └── CiberlabSecurityTests.java       # Pruebas automatizadas de seguridad
```

### 1.3. Puesta en Marcha con Docker Compose
Abre una terminal en la raíz del proyecto y ejecuta:

```bash
docker compose up --build -d
```

Verifica el estado del contenedor y sus recursos asignados:
```bash
docker compose ps
docker stats --no-stream
```

### 1.4. Comprobación de Disponibilidad
Abre tu navegador en:
```text
http://localhost:8080
```
Deberás visualizar el panel interactivo **Purple Team Lab · Seguridad Web** con sus tres módulos activos y la tabla de usuarios inicializada.

Para verificar mediante terminal:
```bash
curl -s http://localhost:8080/api/files/list
```

---

## 2. Módulo 1: Inyección SQL (CWE-89)

### 2.1. Concepto y Causa Raíz a Nivel de Parser SQL
La Inyección SQL (CWE-89) ocurre cuando datos de entrada provistos por el usuario son concatenados directamente dentro de una sentencia SQL sin separación de planos. 

A nivel del motor de base de datos (H2 en este laboratorio), el **Lexer** y el **Parser** transforman la cadena recibida en un **Árbol Sintáctico Abstracto (AST)**. Al concatenar cadenas:
```sql
SELECT id, username, password, role, ssn FROM users WHERE username = '<ENTRADA_USUARIO>'
```
Si el usuario envía `' OR '1'='1`, el parser interpreta las comillas simples como el cierre del literal y la palabra `OR` como un operador lógico booleano de la gramática SQL. Como `'1'='1'` siempre evalúa a verdadero (`TRUE`), la cláusula `WHERE` deja de filtrar por usuario y retorna todos los registros de la tabla, incluyendo contraseñas y datos personales sensibles (SSN).

---

### 2.2. Fase Red Team (Detección y Explotación)
1. En la interfaz web (`http://localhost:8080`), dirígete al **Módulo 1**.
2. En el campo de búsqueda, ingresa el payload clásico de bypass de autenticación:
   ```text
   ' OR '1'='1
   ```
3. Haz clic en **Buscar**.
4. **Observación**:
   - La tabla devuelve los 5 usuarios del sistema (`admin_sec`, `agomez`, `mrodriguez`, `clopez`, `auditor_interno`).
   - Las columnas `Password (Secreto)` y `SSN (PII Sensible)` quedan expuestas en claro.
5. Inspecciona el panel de **Telemetría en Tiempo Real**:
   - Observa la consulta exacta enviada al motor:
     `SELECT id, username, password, role, ssn FROM users WHERE username = '' OR '1'='1'`

Prueba equivalente vía `curl`:
```bash
curl -s "http://localhost:8080/api/users/search?username=%27%20OR%20%271%27=%271" | jq .
```

---

### 2.3. Fase Blue Team (Auditoría SAST y Remediación)

#### Auditoría de Código
Abre el archivo `src/main/java/edu/unsl/ciberlab/controller/UserController.java`.
Ubica la sección vulnerable:
```java
// LÍNEA VULNERABLE:
String sqlVulnerable = "SELECT id, username, password, role, ssn FROM users WHERE username = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sqlVulnerable);
```

**Diagnóstico SAST**:
1. El uso de `Statement` junto con el operador `+` combina comandos y datos en el mismo flujo de análisis léxico.
2. La consulta realiza una proyección amplia (`SELECT *` o incluyendo `password` y `ssn`), violando el **Principio de Mínimo Privilegio de Datos**.

#### Guía de Remediación Paso a Paso
Refactoriza el método utilizando `PreparedStatement` y restringiendo las columnas proyectadas:

```java
// 1. Definir la consulta con parámetros posicionales '?'
//    Nótese que omitimos deliberadamente 'password' y 'ssn'
String sqlSafe = "SELECT id, username, role FROM users WHERE username = ?";

try (Connection conn = dataSource.getConnection();
     PreparedStatement pstmt = conn.prepareStatement(sqlSafe)) {

    // 2. Vincular el parámetro tipado (plano de datos aislado)
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
}
```

**Por qué funciona la mitigación**:
Al usar `PreparedStatement`, el motor SQL compila la plantilla sintáctica **antes** de recibir los valores. El contenido de `username` es transmitido como un literal binario puro; aunque contenga comillas o palabras reservadas como `OR` o `DROP`, el motor nunca las reinterpreta como comandos.

---

## 3. Módulo 2: Cross-Site Scripting Reflejado (CWE-79)

### 3.1. Concepto y Mecanismo de Interpretación en el DOM
El Cross-Site Scripting Reflejado (CWE-79) ocurre cuando una aplicación web recibe datos en una solicitud HTTP y los incluye de inmediato en la respuesta HTML sin la codificación contextual adecuada.

Cuando el navegador del cliente descarga la respuesta con `Content-Type: text/html`, su analizador sintáctico (HTML Parser) interpreta cualquier secuencia `<script>` o manipulador de eventos (como `<img onerror=...>`) como instrucciones de JavaScript para ser ejecutadas en el contexto de seguridad del origen actual. En ausencia de una cabecera `Content-Security-Policy` (CSP), el navegador no tiene forma de distinguir entre el código legítimo del desarrollador y el script inyectado por el atacante.

---

### 3.2. Fase Red Team (Detección y Explotación)
1. En la interfaz web, localiza el **Módulo 2 (Cross-Site Scripting Reflejado)**.
2. Ingresa el siguiente vector didáctico:
   ```html
   <img src=x onerror="alert('XSS_UNSL_EJECUTADO')">
   ```
3. Haz clic en **Generar Saludo**.
4. **Observación**:
   - En el visor de previsualización (Iframe) se dispara la ventana emergente de alerta JavaScript.
5. Revisa el panel de **Telemetría de Cabeceras**:
   - `Content-Security-Policy`: `[NO CONFIGURADA]`
   - `Sanitización`: `Ninguna (Reflejo directo)`

Prueba equivalente vía `curl`:
```bash
curl -i -s "http://localhost:8080/api/profile/greet?name=%3Cimg%20src=x%20onerror=alert(1)%3E"
```
Observa que la respuesta devuelve el código HTML inyectado intacto en el cuerpo y carece de cabeceras defensivas.

---

### 3.3. Fase Blue Team (Auditoría SAST y Remediación)

#### Auditoría de Código
Abre `src/main/java/edu/unsl/ciberlab/controller/ProfileController.java`:
```java
// LÍNEA VULNERABLE:
String htmlVulnerable = "...<h2>¡Bienvenido/a a la plataforma, " + name + "!</h2>...";
return ResponseEntity.ok().headers(headers).body(htmlVulnerable);
```

#### Guía de Remediación Paso a Paso
Aplica **Defensa en Profundidad**:
1. **Sanitización Contextual**: Utiliza `Encode.forHtml()` de la biblioteca `org.owasp.encoder:encoder`.
2. **Política de Seguridad de Contenido (CSP)**: Inyecta cabeceras HTTP que deshabiliten la ejecución de scripts no autorizados.

Edita `ProfileController.java`:
```java
import org.owasp.encoder.Encode;
import org.springframework.http.HttpHeaders;

// 1. Codificar la entrada para el contexto del cuerpo HTML
String safeName = Encode.forHtml(name);

// 2. Establecer cabeceras defensivas
HttpHeaders headers = new HttpHeaders();
headers.set("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'");
headers.set("X-Content-Type-Options", "nosniff");

String safeHtml = """
    <!DOCTYPE html>
    <html lang="es">
    <body>
        <h2>¡Bienvenido/a a la plataforma, %s!</h2>
    </body>
    </html>
    """.formatted(safeName);

return ResponseEntity.ok()
        .headers(headers)
        .body(safeHtml);
```

**Por qué funciona la mitigación**:
- `Encode.forHtml()` sustituye caracteres de control (`<`, `>`, `"`, `'`, `&`) por sus entidades numéricas seguras (`&lt;`, `&gt;`, `&#39;`). El navegador renderiza el texto visiblemente pero no crea nuevos nodos DOM ejecutables.
- `Content-Security-Policy: script-src 'none'` instruye al motor del navegador a bloquear de forma terminante cualquier intento de ejecución de scripts, sirviendo como barrera secundaria si fallara la sanitización.

---

## 4. Módulo 3: Salto de Directorio / Path Traversal (CWE-22)

### 4.1. Concepto de Resolución de Rutas Relativas y Escape
El Salto de Directorio (CWE-22) surge cuando una ruta de archivo local es construida concatenando entradas no confiables a un directorio base.

En sistemas de archivos estándar (POSIX y Windows), la secuencia especial `../` (dot-dot-slash) representa el directorio padre. Cuando una función del sistema operativo procesa una ruta como:
```text
/app/storage/public/../confidential/flag.txt
```
La secuencia `../` anula el segmento `public/`, resolviendo la ruta efectiva hacia:
```text
/app/storage/confidential/flag.txt
```
Si la aplicación no comprueba que la ruta canónica final permanezca dentro del directorio raíz previsto, un atacante puede leer archivos de configuración, secretos, claves privadas o datos de otros usuarios del sistema.

---

### 4.2. Fase Red Team (Detección y Explotación)
1. En la interfaz web, localiza el **Módulo 3 (Path Traversal)**.
2. Selecciona o ingresa el nombre del archivo:
   ```text
   ../confidential/flag.txt
   ```
3. Haz clic en **Descargar / Leer**.
4. **Observación**:
   - El visor de contenido muestra el archivo confidencial con la bandera del laboratorio:
     `FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}`
5. Revisa el panel de **Telemetría POSIX**:
   - `Ruta Canónica Resuelta`: `/app/storage/confidential/flag.txt`
   - `targetPath.startsWith(baseDir)`: `FALSE (ESCAPE EXITOSO)`

Prueba equivalente vía `curl`:
```bash
curl -s "http://localhost:8080/api/files/download?filename=../confidential/flag.txt"
```

---

### 4.3. Fase Blue Team (Auditoría SAST y Remediación)

#### Auditoría de Código
Abre `src/main/java/edu/unsl/ciberlab/controller/FileController.java`:
```java
// LÍNEA VULNERABLE:
Path publicRoot = getStorageRoot().resolve("public");
File targetFile = new File(publicRoot.toFile(), filename);
byte[] fileBytes = Files.readAllBytes(targetFile.toPath());
```

**Diagnóstico SAST**:
El constructor `new File(File parent, String child)` no previene que `child` contenga secuencias relativas que apunten a ubicaciones fuera de `parent`.

#### Guía de Remediación Paso a Paso
Utiliza `java.nio.file.Path`, normaliza la ruta resolviendo los puntos dobles con `normalize()`, y verifica la contención estricta con `startsWith()`:

```java
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import org.springframework.http.HttpStatus;

// 1. Obtener la ruta base absoluta y normalizada
Path baseDir = getStorageRoot().resolve("public").toAbsolutePath().normalize();

// 2. Resolver la entrada del usuario y normalizar para colapsar los '../'
Path targetPath = baseDir.resolve(filename).normalize();

// 3. Verificación de frontera de seguridad (Boundary Check)
if (!targetPath.startsWith(baseDir)) {
    log.warn("[ALERTA SEGURIDAD] Intento de Path Traversal bloqueado: {}", targetPath);
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body("ALERTA DE SEGURIDAD (CWE-22): Acceso fuera del directorio autorizado denegado.");
}

// 4. Comprobar que el archivo exista y sea un archivo regular
if (!Files.exists(targetPath) || !Files.isRegularFile(targetPath)) {
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Archivo no encontrado.");
}

byte[] fileBytes = Files.readAllBytes(targetPath);
```

**Por qué funciona la mitigación**:
El método `normalize()` elimina redundantemente cualquier segmento `.`, `..` o separador duplicado. Posteriormente, `targetPath.startsWith(baseDir)` garantiza matemáticamente que el prefijo absoluto del destino coincida con el árbol permitido. Si la ruta intenta descender por encima de `baseDir`, la condición es falsa y se retorna `403 Forbidden`.

---

## 5. Verificación Final y Recompilación de la Solución

Una vez que hayas analizado y corregido el código en tus archivos locales de Java:

### 5.1. Ejecución de Pruebas Unitarias Automatizadas
En tu terminal local ejecuta:
```bash
./mvnw test
```
(O con Maven instalado globalmente: `mvn test`).
Todas las 6 pruebas de seguridad del conjunto `CiberlabSecurityTests` deben finalizar con éxito (`BUILD SUCCESS`).

### 5.2. Recompilación del Contenedor Docker
Para desplegar la versión remediada dentro de Docker:
```bash
docker compose up --build -d
```

### 5.3. Validación de Post-Remediación
Prueba los tres vectores anteriores mediante `curl`:

1. **Prueba SQLi**:
   ```bash
   curl -s "http://localhost:8080/api/users/search?username=%27%20OR%20%271%27=%271&mode=safe"
   ```
   *Resultado esperado*: 0 registros retornados, ninguna contraseña expuesta.

2. **Prueba XSS**:
   ```bash
   curl -i -s "http://localhost:8080/api/profile/greet?name=%3Cscript%3Ealert(1)%3C/script%3E&mode=safe" | grep -i "content-security-policy"
   ```
   *Resultado esperado*: Presencia de la cabecera `Content-Security-Policy: default-src 'self'; script-src 'none'`.

3. **Prueba Path Traversal**:
   ```bash
   curl -i -s "http://localhost:8080/api/files/download?filename=../confidential/flag.txt&mode=safe"
   ```
   *Resultado esperado*: Respuesta HTTP `403 Forbidden` denegando el acceso.

---
¡Felicitaciones! Has completado el ciclo completo **Purple Team**: identificar la causa raíz, explotar la vulnerabilidad en laboratorio, inspeccionar la telemetría del sistema, implementar la remediación en código Java y validar el endurecimiento final de la plataforma.
