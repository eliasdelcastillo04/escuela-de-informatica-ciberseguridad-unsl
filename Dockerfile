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

# Copiar archivos de almacenamiento didácticos completos (incluyendo pistas en confidential/flag.txt)
COPY storage/ /app/storage/

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
