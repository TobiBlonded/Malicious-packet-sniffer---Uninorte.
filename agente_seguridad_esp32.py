"""
Agente de IA para clasificar peligrosidad de eventos de red capturados
por el ESP32. Usa Groq (gratis, sin tarjeta, API compatible con el
formato de OpenAI) como motor de razonamiento, y Exa como tool real
de búsqueda web.

Usamos 'requests' en vez de un SDK oficial para evitar problemas de
compilación nativa en Windows -- requests es puro Python.

Instalar dependencias:
    pip install requests exa-py python-dotenv fastapi uvicorn pydantic

Configurar las keys en tu archivo .env:
    GROQ_API_KEY=tu-key-de-groq
    EXA_API_KEY=tu-key-de-exa

Correr:
    python agente_seguridad_esp32.py
"""

import os
import json
import requests
from dotenv import load_dotenv
from exa_py import Exa

load_dotenv()

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_API_KEY = os.environ["GROQ_API_KEY"]

# Modelos con soporte de tools en Groq (gratis, sin tarjeta):
# "llama-3.3-70b-versatile", "llama-3.1-8b-instant"
MODELO = "qwen/qwen3.6-27b"

exa = Exa(api_key=os.environ["EXA_API_KEY"])

# -----------------------------------------------------------------
# TOOLS -- formato OpenAI (function calling), el que espera OpenRouter
# sin importar qué modelo esté corriendo atrás.
# -----------------------------------------------------------------
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "consultar_historial_mac",
            "description": (
                "Devuelve cuántas veces se vio esta MAC address en eventos "
                "sospechosos anteriores, y si ya fue marcada como maliciosa."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "mac": {"type": "string", "description": "MAC address a consultar"}
                },
                "required": ["mac"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verificar_bssid_conocido",
            "description": (
                "Verifica si un BSSID (dirección del punto de acceso) "
                "corresponde a una red conocida/confiable en nuestra red local."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "bssid": {"type": "string", "description": "BSSID del access point"}
                },
                "required": ["bssid"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "buscar_info_amenaza",
            "description": (
                "Busca información real en internet sobre un tipo de ataque WiFi, "
                "un fabricante de MAC, o técnicas de mitigación."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "consulta": {
                        "type": "string",
                        "description": "Qué buscar, ej: 'mitigación ataque evil twin WiFi'",
                    }
                },
                "required": ["consulta"],
            },
        },
    },
]

# -----------------------------------------------------------------
# CÓDIGO REAL de cada tool
# -----------------------------------------------------------------
HISTORIAL_MACS = {}
BSSIDS_CONOCIDOS = {"AA:BB:CC:DD:EE:FF"}  # BSSID real del router de pruebas


def consultar_historial_mac(mac: str) -> dict:
    veces = HISTORIAL_MACS.get(mac, 0)
    HISTORIAL_MACS[mac] = veces + 1
    return {"mac": mac, "veces_vista_antes": veces, "marcada_maliciosa": veces > 3}


def verificar_bssid_conocido(bssid: str) -> dict:
    return {"bssid": bssid, "es_confiable": bssid in BSSIDS_CONOCIDOS}


def buscar_info_amenaza(consulta: str) -> dict:
    resultados = exa.search_and_contents(
        consulta,
        num_results=3,
        text={"max_characters": 500},
    )
    hallazgos = [
        {"titulo": r.title, "url": r.url, "resumen": r.text}
        for r in resultados.results
    ]
    return {"consulta": consulta, "hallazgos": hallazgos}


TOOL_FUNCTIONS = {
    "consultar_historial_mac": consultar_historial_mac,
    "verificar_bssid_conocido": verificar_bssid_conocido,
    "buscar_info_amenaza": buscar_info_amenaza,
}

SYSTEM_PROMPT = """Sos un analista de ciberseguridad especializado en redes WiFi.
Recibís eventos detectados por un ESP32 en modo promiscuo (deauth frames,
beacons sospechosos, Evil Twin, etc). Tu trabajo es:
1. Usar las tools disponibles para investigar contexto adicional si hace falta.
2. Clasificar el evento en: BAJO, MEDIO, ALTO o CRITICO.
3. Explicar en 2-3 líneas por qué, en lenguaje simple.
4. Sugerir una acción concreta.
Respondé siempre en español."""


SYSTEM_PROMPT = """Eres un analista de ciberseguridad especializado en redes WiFi.
Analiza eventos detectados por un ESP32 en modo promiscuo, como deauth,
disassoc, beacons sospechosos o Evil Twin.

Clasifica el riesgo como BAJO, MEDIO, ALTO o CRITICO. Trata los eventos como
indicadores de riesgo, no como ataques confirmados. Si el evento fue marcado
como simulado o de prueba, indicalo claramente y no recomiendes bloquear
dispositivos reales.

Responde siempre en espanol y usa exactamente este formato:

Nivel: [BAJO|MEDIO|ALTO|CRITICO]
Motivo: [dos frases breves y claras]
Accion recomendada: [una accion concreta, proporcional y segura]

No uses Markdown, no agregues secciones adicionales y no inventes datos."""


def limpiar_texto_respuesta(texto: str) -> str:
    """Corrige mojibake frecuente y elimina caracteres de reemplazo."""
    texto = texto.replace("\ufffd", "")
    if "\u00c3" in texto:
        try:
            return texto.encode("latin-1").decode("utf-8")
        except UnicodeError:
            pass
    return texto


def llamar_groq(mensajes: list) -> dict:
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": MODELO,
        "messages": mensajes,
        "tools": TOOLS,
        "max_tokens": 512,
        "reasoning_effort": "none",
    }
    resp = requests.post(GROQ_URL, headers=headers, json=body, timeout=60)
    if not resp.ok:
        print("=== Error de Groq (detalle) ===")
        print(resp.status_code, resp.text)
    resp.raise_for_status()
    return resp.json()


def analizar_evento(evento: dict) -> str:
    mensajes = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Analizá este evento de red:\n{json.dumps(evento, indent=2)}",
        },
    ]

    while True:
        data = llamar_groq(mensajes)
        mensaje = data["choices"][0]["message"]

        tool_calls = mensaje.get("tool_calls")

        # Si no pidió usar ninguna tool, ya tenemos la respuesta final
        if not tool_calls:
            return limpiar_texto_respuesta(mensaje.get("content", ""))

        # Guardamos el mensaje del asistente (con los tool_calls) en el historial
        mensajes.append(mensaje)

        # Ejecutamos cada tool que pidió y devolvemos el resultado
        for tool_call in tool_calls:
            nombre_funcion = tool_call["function"]["name"]
            argumentos = json.loads(tool_call["function"]["arguments"])
            funcion = TOOL_FUNCTIONS[nombre_funcion]
            resultado = funcion(**argumentos)

            mensajes.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call["id"],
                    "content": json.dumps(resultado),
                }
            )
        # el while vuelve a llamar al modelo con los resultados incluidos


if __name__ == "__main__":
    evento_ejemplo = {
        "tipo": "deauth_flood",
        "mac_origen": "12:34:56:78:9A:BC",
        "bssid_objetivo": "AA:BB:CC:DD:EE:FF",
        "paquetes_por_segundo": 45,
        "canal": 6,
    }

    resultado = analizar_evento(evento_ejemplo)
    print("=== Clasificación del agente ===")
    print(resultado)
