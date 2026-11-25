# Laboratorio de Seguridad en Aplicaciones Web - UNSL (Purple Team)

Plataforma práctica de ciberseguridad web orientada al **Taller de Seguridad Web (3 Jornadas · 9 horas)** de la **Universidad Nacional de San Luis (UNSL)**. Diseñada para operar **100% offline** en el servidor local de la Sala de Máquinas Linux con múltiples estudiantes concurrentes.

---

## Arquitectura Didáctica y Multi-Estudiante

- **Aislamiento en Aula Compartida**:
  - Consultas SQL vulnerables ejecutadas con usuario H2 **Read-Only** (`CIBERLAB_RO`) y `queryTimeout` de 2s, impidiendo `DROP`/`DELETE`/`SHUTDOWN`.
  - Consola `/h2-console` deshabilitada por defecto.
  - Path Traversal (`CWE-22`) confinado al directorio `storage/` (≤ 64 KB) en modo vulnerable.
  - **XSS Almacenado** persistente en H2 pero **aislado por sesión** (`X-Lab-Session`) para evitar contaminación entre estudiantes.
  - **Rate Limiting** por IP (`RateLimitFilter`) para evitar saturación por scripts o bucles en aula.
- **Cobertura del Cronograma (3 Jornadas)**:
  - **Día 1**: Path Traversal (`CWE-22`) + Cuestionario práctico + SQL Injection Parte 1 (Auth Bypass `CWE-89`).
  - **Día 2**: SQL Injection Parte 2 (`UNION SELECT` sobre `audit_secrets` + Blind SQLi `/api/users/check`), XSS Reflejado (impacto en sesión) + XSS Almacenado + Cuestionario y CSP (`CWE-79`).
  - **Día 3**: Competencia CTF con **Ranking en tiempo real** (Top 3 para premiación) y retos encadenados.
- **Panel Docente**: Control de jornada activa (`DIA_1`, `DIA_2`, `DIA_3_CTF`, `LIBRE`), Modo Demo en vivo, reinicio de Ranking y exportación CSV.

---

## Despliegue en Sala de Máquinas (Linux)

### Opción 1: Ejecución directa con Java 17 / Maven (Recomendada en Sala)
```bash
# Definir clave docente antes de iniciar (opcional, por defecto: unsl-docente-2026)
export DOCENTE_PASSWORD="tu_clave_segura_docente"

# Compilar y empaquetar
./mvnw clean package

# Iniciar servidor en puerto 8080
java -jar target/laboratorio-seguridad-web-1.0.0-SNAPSHOT.jar
```

### Opción 2: Docker Compose
```bash
DOCENTE_PASSWORD="tu_clave_segura_docente" docker compose up --build -d
```

Accede desde cualquier puesto de la red interna a `http://<IP-DEL-SERVIDOR>:8080`.

---

## Pruebas Automatizadas
```bash
./mvnw test
```
Incluye pruebas Red Team, Blue Team, aislamiento multi-estudiante (SQLi Read-Only, Sandbox `storage/`, aislamiento de sesiones XSS, `/h2-console` deshabilitada, Rate Limiting), cuestionarios y Ranking CTF.
