# Defensor ESP32: analizador de eventos Wi-Fi con IA

## Introduccion

Defensor ESP32 es un prototipo para un hackathon que detecta actividad Wi-Fi
sospechosa y la presenta en un dashboard local. Un ESP32-S3 escucha tramas de
gestion en el canal de la red a la que esta conectado y reporta eventos de
`deauth_flood` y `disassoc_flood` al servidor. El servidor usa un agente de IA
para asignar un nivel de riesgo y proponer una accion segura.

El proyecto esta pensado para redes y equipos bajo autorizacion. El boton de
prueba no transmite tramas Wi-Fi: envia un evento simulado al servidor para
demostrar el flujo completo sin afectar dispositivos.

## Arquitectura

```text
ESP32 -> POST /evento -> cola del servidor -> agente IA -> dashboard
```

El servidor procesa un evento por vez para respetar las cuotas del proveedor de
IA. Eventos iguales recibidos durante ocho segundos se omiten para evitar
clasificaciones repetidas y errores por limite de solicitudes.

## Componentes

- `esp32/esp32_defensor/esp32_defensor.ino`: firmware del ESP32-S3.
- `servidor.py`: API FastAPI, cola de clasificacion y endpoints del dashboard.
- `agente_seguridad_esp32.py`: clasificador que usa Groq y Exa.
- `static/dashboard.html`: dashboard que se actualiza cada dos segundos.

## Dashboard

El panel muestra el estado de conexion, total de eventos, eventos criticos,
alertas de alto riesgo y elementos pendientes. Incluye un filtro por nivel y
una tarjeta por evento con origen, BSSID, canal, tasa de paquetes y analisis.

Endpoints utiles:

- `GET /salud`: estado del servidor y longitud de la cola.
- `GET /eventos`: historial reciente en JSON.
- `GET /resumen`: contadores que alimentan el dashboard.
- `POST /evento`: entrada usada por el ESP32.

## Requisitos

- Python 3.13 y el entorno virtual `venv` del proyecto.
- ESP32-S3 con las librerias WiFi, HTTPClient, ArduinoJson y esp_wifi.
- Claves de Groq y Exa en el archivo `.env`.
- PC y ESP32 conectados a la misma red Wi-Fi.

## Configuracion

1. Copia `env.example` como `.env` y completa las claves:

   ```env
   GROQ_API_KEY=tu_clave
   EXA_API_KEY=tu_clave
   ```

2. Confirma la IP local de la PC en la red del router de prueba:

   ```powershell
   ipconfig
   ```

3. En el firmware, actualiza `SERVER_URL` con esa IP:

   ```cpp
   const char* SERVER_URL = "http://TU_IP:8000/evento";
   ```

4. Compila y carga el archivo `.ino` al ESP32.

## Iniciar el servidor

Desde la carpeta del proyecto:

```powershell
.\venv\Scripts\Activate.ps1
uvicorn servidor:app --host 0.0.0.0 --port 8000
```

Abre el dashboard en el navegador:

```text
http://localhost:8000/
```

Tambien puede abrirse desde otro equipo de la misma red usando
`http://TU_IP:8000/`.

## Boton de prueba

Conecta un pulsador normalmente abierto entre los siguientes pines:

```text
GPIO 4 del ESP32 --- pulsador --- GND del ESP32
```

No conectes el boton a 5 V ni a 3.3 V. El firmware usa `INPUT_PULLUP`: el pin
permanece en alto cuando el boton esta suelto y pasa a bajo al presionarlo.

Cada pulsacion envia un evento seguro de prueba con:

- Tipo: `deauth_flood_simulado`
- MAC simulada: `DE:AD:BE:EF:00:01`
- Intensidad: 25 paquetes por segundo

En el Monitor Serie debe aparecer:

```text
>>> Prueba de deauth_flood enviada por boton
Evento enviado -> HTTP 202
```

El evento aparecera en el dashboard en un maximo de dos segundos. Espera unos
segundos entre pulsaciones para no superar el limite de solicitudes de Groq.

## Interpretar resultados

- `BAJO`: actividad aislada o con poco contexto de riesgo.
- `MEDIO`: requiere observacion adicional.
- `ALTO`: patron sospechoso que requiere revisar la red.
- `CRITICO`: actividad reiterada o con alto impacto potencial.

Una clasificacion es una senal de apoyo para el analisis, no una confirmacion
automatica de un ataque. Para eventos simulados, el agente debe indicar que se
trata de una prueba y sugerir acciones no disruptivas.

## Diagnostico rapido

- `HTTP -1` en el ESP32: el ESP32 no puede llegar a la IP del servidor. Revisa
  que ambos equipos esten en la misma red y que `SERVER_URL` tenga la IP actual.
- `HTTP 202`: el servidor recibio el evento correctamente.
- No hay eventos en el panel: recarga `http://TU_IP:8000/` con `Ctrl + F5`.
- Error `429` de Groq: espera unos segundos antes de enviar otro evento.
