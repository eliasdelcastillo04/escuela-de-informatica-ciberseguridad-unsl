package edu.unsl.ciberlab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Aplicación principal del Laboratorio de Seguridad Web (Purple Team).
 * Diseñado para talleres universitarios sobre CWE-89, CWE-79 y CWE-22.
 */
@SpringBootApplication
public class CiberlabApplication {

    public static void main(String[] args) {
        SpringApplication.run(CiberlabApplication.class, args);
    }
}
