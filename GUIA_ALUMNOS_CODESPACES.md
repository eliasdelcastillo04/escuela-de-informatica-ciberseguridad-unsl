# Guía de Ingreso para Alumnos — GitHub Codespaces

Esta guía explica cómo iniciar el **Laboratorio de Seguridad Web (UNSL)** directamente desde el navegador, **sin instalar Java, Maven ni Docker** en tu computadora.

---

## 1. Antes de empezar (en tu casa o antes de la clase)

1. Creá una **cuenta gratuita en GitHub** en [github.com/signup](https://github.com/signup) (no requiere tarjeta de crédito).
2. Usá preferentemente **Google Chrome, Edge o Firefox** (Safari suele bloquear la apertura del puerto por cookies entre sitios).

---

## 2. Abrir tu entorno en Codespaces

1. Ingresá al repositorio del taller:
   `https://github.com/eliasdelcastillo04/escuela-de-informatica-ciberseguridad-unsl`
2. Iniciá sesión con tu cuenta de GitHub.
3. Hacé clic en el botón verde **`<> Code`**.
4. Elegí la pestaña **`Codespaces`**.
5. Hacé clic en **`Create codespace on main`**.

> Esperá entre **30 y 60 segundos** mientras se prepara la máquina y se cargan los archivos del proyecto.

---

## 3. Levantar el servidor del laboratorio

1. En la parte inferior vas a ver la pestaña **`Terminal`**. Hacé clic ahí.
2. Escribí el siguiente comando y presioná **Enter**:

   ```bash
   ./mvnw spring-boot:run
   ```

3. Esperá unos 15–20 segundos hasta que aparezca un mensaje similar a:
   `Started ...Application in ... seconds`

---

## 4. Abrir la página web del laboratorio

Tenés dos formas de abrirlo:

- **Opción A (más simple, sin errores de navegador):**
  1. Hacé clic en la pestaña **`Ports`** (al lado de `Terminal`).
  2. En la fila del puerto **`8080`**, hacé clic en el ícono de **Preview in Editor** (el cuadradito con una lupa, justo a la izquierda del globo).
  3. El laboratorio se abrirá en una pestaña dentro del mismo editor.

- **Opción B (en una pestaña aparte del navegador):**
  1. En la pestaña **`Ports`**, en la fila **`8080`**, hacé clic en el ícono del **globo (`Open in Browser`)**.
  2. Si aparece **`HTTP ERROR 401`**: volvé a la pestaña **`Ports`**, hacé clic derecho sobre **`Private`** en la columna *Visibility* → **`Port Visibility` → `Public`**, y recargá la pestaña del navegador.

---

## 5. Si editás código Java o querés reiniciar

1. Andá a la **`Terminal`** y presioná **`Ctrl + C`** para detener el servidor.
2. Volvé a ejecutar:
   ```bash
   ./mvnw spring-boot:run
   ```

---

## 6. Si el Codespace se pausa en un recreo

Por inactividad (30 minutos), GitHub suspende la máquina para ahorrar tus horas gratuitas:
- Tus archivos **no se pierden**.
- Solo hacé clic en **`Resume`** (o recargá la pestaña) y volvé a correr `./mvnw spring-boot:run` en la Terminal.

---

## 7. Al finalizar el taller (importante)

Para no seguir consumiendo tu cuota gratuita mensual:
1. Entrá a [github.com/codespaces](https://github.com/codespaces).
2. En tu codespace del taller, hacé clic en los **`...`** → **`Stop codespace`** (o **`Delete`** si ya terminaron las 3 jornadas).
