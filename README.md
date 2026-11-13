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

## 🛠️ Estructura del Repositorio

- `Dockerfile`: Configuración multi-stage sin privilegios (usuario `appuser`).
- `docker-compose.yml`: Despliegue con límites de recursos (CPU y RAM).
- `pom.xml`: Configuración Maven, Spring Boot y dependencias de seguridad (OWASP Java HTML Sanitizer / Encoder).
- `storage/`: Directorio de archivos simulados para pruebas de Path Traversal (`public/` y `confidential/`).
- `src/main/`: Código fuente de la aplicación, controladores vulnerables/seguros y frontend interactivo.
- `src/test/`: Suite de pruebas unitarias y de integración de seguridad.
- [LAB_MANUAL.md](LAB_MANUAL.md): **Manual completo de laboratorio** con guía paso a paso de explotación, telemetría y remediación.

---

## 📖 Manual de Ejercicios

Consulta la guía completa de actividades en:
👉 **[LAB_MANUAL.md](LAB_MANUAL.md)**
