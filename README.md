# Laboratorio de Seguridad en Aplicaciones Web - UNSL

Proyecto práctico de ciberseguridad con enfoque **Purple Team** (Detección, Telemetría y Remediación) desarrollado para la **Universidad Nacional de San Luis (UNSL)**.

Construido sobre **Java 17 / Spring Boot 3.3.x**, este entorno simula vulnerabilidades comunes del Top 10 de OWASP para analizar sus vectores de explotación y aplicar técnicas defensivas de sanitización, consultas parametrizadas, control de rutas y telemetría de seguridad.

---

## 🚀 Inicio Rápido con Docker

La forma recomendada de inicializar el laboratorio es utilizando **Docker Compose**:

```bash
docker compose up --build -d
```

Una vez levantado el contenedor:
- Accede a la interfaz web interactiva en: [http://localhost:8080](http://localhost:8080)
- Monitorea logs y telemetría de seguridad en tiempo real con:
  ```bash
  docker compose logs -f ciberlab-app
  ```

Para detener el entorno:
```bash
docker compose down
```

---

## 💻 Ejecución Nativa en Ubuntu / Linux (Sin Docker)

Si prefieres ejecutar el proyecto directamente en tu sistema Ubuntu con **Java 17+**:

### 1. Prerrequisitos en Ubuntu
```bash
sudo apt update
sudo apt install -y openjdk-17-jdk
```

### 2. Ejecutar la Aplicación Web con `java -jar`
Empaqueta el ejecutable y levanta la aplicación:
```bash
# Compilar y empaquetar el JAR
./mvnw clean package -DskipTests

# Iniciar la aplicación con el comando java
java -jar target/laboratorio-seguridad-web-1.0.0-SNAPSHOT.jar
```
La aplicación estará disponible en [http://localhost:8080](http://localhost:8080).

### 3. Ejecutar las Pruebas de Seguridad Automatizadas
```bash
# Ejecutar todas las pruebas de seguridad con Maven Wrapper
./mvnw test

# O ejecutar únicamente la clase de test de seguridad
./mvnw test -Dtest=CiberlabSecurityTests
```

---

## ✨ Características Principales del Laboratorio

- **Intranet Retro Universitaria (Edición 2003)** dentro de un escritorio **Windows XP Luna**: Se abre automáticamente en Internet Explorer 6.0 con banners ASCII, diagramas Unicode y tipografía de alto contraste (`#0d1117` con texto verde fósforo y ámbar).
- **Progresión Incremental por Fases y Módulos**:
  - Desbloqueo secuencial: **Módulo 1 (CWE-89 SQLi)** ➔ **Módulo 2 (CWE-79 XSS)** ➔ **Módulo 3 (CWE-22 Path Traversal)** (con opción de **Modo Docente** para desbloqueo libre).
  - 4 Fases guiadas por módulo: `1. Teoría & AST/DOM` ➔ `2. Ataque Red Team` ➔ `3. Telemetría de Servidor` ➔ `4. Remediación Blue Team`.
- **Sistema CTF Integrado (`/api/ctf`)**: 6 retos oficiales (3 Red Team + 3 Blue Team), validador de banderas `FLAG{...}` desde la UI o desde la terminal MS-DOS (`submit <flag>`), y persistencia automática en el navegador.
- **Terminal MS-DOS Interactiva**: Soporta comandos reales como `ctf`, `submit <FLAG>`, `cat <archivo>`, `curl <endpoint>`, `unlock`, `help`, `cls`.

---

## 🛠️ Estructura del Repositorio

- `.github/workflows/ci.yml`: Workflow de GitHub Actions para compilación y pruebas automatizadas de seguridad.
- `Dockerfile`: Configuración multi-stage sin privilegios (usuario `ciberlab`).
- `docker-compose.yml`: Despliegue con límites de recursos (CPU y RAM).
- `pom.xml`: Configuración Maven, Spring Boot 3.3.5 y dependencias de seguridad (`org.owasp.encoder`).
- `storage/`: Directorio de archivos simulados para pruebas de Path Traversal (`public/` y `confidential/`).
- `src/main/java/edu/unsl/ciberlab/controller/`: Controladores de los 3 módulos (`UserController`, `ProfileController`, `FileController`) y motor CTF (`CtfController`).
- `src/main/resources/static/index.html`: Escritorio Windows XP + Intranet Retro UNSL 2000s + Terminal MS-DOS + CTF Tracker.
- `src/test/`: Suite de 8 pruebas unitarias y de integración de seguridad (`CiberlabSecurityTests`).
- [LAB_MANUAL.md](LAB_MANUAL.md): **Manual completo de laboratorio** con guía paso a paso de explotación, telemetría y remediación.

---

## 📖 Manual de Ejercicios

Consulta la guía completa de actividades y dinámica CTF en:
👉 **[LAB_MANUAL.md](LAB_MANUAL.md)**

