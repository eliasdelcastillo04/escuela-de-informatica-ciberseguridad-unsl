# ==============================================================================
# ETAPA 1: BUILDER (Compilación y Empaquetamiento Maven con Eclipse Temurin 17)
# ==============================================================================
FROM maven:3.9.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Copiar descriptor de dependencias para aprovechar el caché de Docker
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copiar código fuente y compilar artefacto JAR
COPY src ./src
RUN mvn clean package -DskipTests -B

# ==============================================================================
# ETAPA 2: RUNTIME (Entorno de Ejecución Seguro y Mínimo con JRE 17)
# ==============================================================================
FROM eclipse-temurin:17-jre-jammy

LABEL maintainer="Universidad Nacional de San Luis - Ciberseguridad" \
      description="Contenedor seguro para Laboratorio Web Purple Team (CWE-89, CWE-79, CWE-22)"

WORKDIR /app

# Crear usuario y grupo de sistema sin privilegios (Hardening de contenedor)
RUN groupadd -r ciberlab && useradd -r -g ciberlab -s /sbin/nologin -d /app ciberlab

# Crear estructura de almacenamiento de archivos para las pruebas didácticas
RUN mkdir -p /app/storage/public /app/storage/confidential

# Archivo 1 público: Reporte de auditoría
RUN echo "==============================================================\n\
UNIVERSIDAD NACIONAL DE SAN LUIS - REPORTE DE AUDITORÍA 2026\n\
==============================================================\n\
Fecha: 2026-11-03\n\
Estado General: OPERATIVO CON OBSERVACIONES\n\
Servidores Auditados: 12 nodos\n\
Vulnerabilidades Críticas Detectadas: 3 (En proceso de remediación didáctica)\n\
==============================================================" > /app/storage/public/reporte_auditoria_2026.txt

# Archivo 2 público: Política de seguridad
RUN echo "==============================================================\n\
POLÍTICA DE SEGURIDAD DE LA INFORMACIÓN - LABORATORIO WEB\n\
==============================================================\n\
1. Separación de planos de control y datos en consultas SQL.\n\
2. Codificación contextual para mitigar XSS.\n\
3. Validación canónica de rutas con startsWith().\n\
==============================================================" > /app/storage/public/politica_seguridad.txt

# Archivo confidencial: Flag del ejercicio CWE-22 (fuera del directorio público)
RUN echo "FLAG{UNSL_PURPLE_TEAM_PATH_TRAVERSAL_MASTERED_2026}\n\
[CONFIDENCIAL] Acceso no autorizado a registros sensibles de la Universidad.\n\
CWE-22 explotado con éxito. Remediación requerida en FileController.java." > /app/storage/confidential/flag.txt

# Copiar el artefacto compilado desde la etapa builder
COPY --from=builder /build/target/*.jar /app/app.jar

# Asignar propiedad de los archivos al usuario no privilegiado ciberlab
RUN chown -R ciberlab:ciberlab /app

# Cambiar al usuario de sistema sin privilegios
USER ciberlab

# Puerto de escucha del servidor Spring Boot
EXPOSE 8080

# Parámetros optimizados para contenedores con límite de 512MB de RAM
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
