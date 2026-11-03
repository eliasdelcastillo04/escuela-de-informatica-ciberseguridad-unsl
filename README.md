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
