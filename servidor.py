"""Servidor de ingesta y dashboard para eventos Wi-Fi del ESP32."""
import asyncio
import os
import re
import secrets
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from agente_seguridad_esp32 import analizar_evento

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
MAX_EVENTOS = 200
VENTANA_DUPLICADOS_SEGUNDOS = 8
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
NIVELES = ("CRITICO", "ALTO", "MEDIO", "BAJO")

class EventoEntrada(BaseModel):
    tipo: str = Field(min_length=2, max_length=50)
    mac_origen: str
    bssid_objetivo: str
    paquetes_por_segundo: float = Field(ge=0, le=100_000)
    canal: int = Field(ge=1, le=196)

    @field_validator("mac_origen", "bssid_objetivo")
    @classmethod
    def validar_mac(cls, valor: str) -> str:
        valor = valor.upper()
        if not MAC_RE.fullmatch(valor):
            raise ValueError("debe tener formato MAC AA:BB:CC:DD:EE:FF")
        return valor

class Estado:
    def __init__(self) -> None:
        self.cola: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.eventos: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTOS)
        self.clientes: set[WebSocket] = set()
        self.ultimos_eventos: dict[tuple[str, str, str], float] = {}

    async def publicar(self, mensaje: dict[str, Any]) -> None:
        for cliente in self.clientes.copy():
            try:
                await cliente.send_json(mensaje)
            except Exception:
                self.clientes.discard(cliente)

estado = Estado()
def ahora() -> str: return datetime.now(timezone.utc).isoformat()
def nivel_desde_respuesta(respuesta: str) -> str:
    for nivel in NIVELES:
        if re.search(rf"\b{nivel}\b", respuesta.upper()): return nivel
    return "SIN_CLASIFICAR"


def resumen() -> dict[str, int]:
    eventos = list(estado.eventos)
    return {"total": len(eventos), "pendientes": sum(e["estado"] == "pendiente" for e in eventos), "errores": sum(e["estado"] == "error" for e in eventos), "criticos": sum(e["nivel"] == "CRITICO" for e in eventos), "altos": sum(e["nivel"] == "ALTO" for e in eventos)}

async def procesar_eventos() -> None:
    while True:
        registro = await estado.cola.get()
        try:
            respuesta = await asyncio.to_thread(analizar_evento, registro["evento"])
            registro.update(estado="completado", nivel=nivel_desde_respuesta(respuesta), analisis=respuesta, procesado_en=ahora())
        except Exception as error:
            registro.update(estado="error", nivel="ERROR", analisis="No se pudo clasificar el evento.", detalle_error=str(error), procesado_en=ahora())
        finally:
            estado.cola.task_done()
            await estado.publicar({"tipo": "evento_actualizado", "evento": registro})

@asynccontextmanager
async def ciclo_vida(_: FastAPI):
    tarea = asyncio.create_task(procesar_eventos())
    yield
    tarea.cancel()
    try: await tarea
    except asyncio.CancelledError: pass

app = FastAPI(title="Defensor ESP32", lifespan=ciclo_vida)

def verificar_token(token: str | None) -> None:
    esperado = os.getenv("ESP32_INGEST_TOKEN")
    if esperado and not token: raise HTTPException(401, "Falta X-ESP32-Token")
    if esperado and not secrets.compare_digest(token, esperado): raise HTTPException(403, "X-ESP32-Token inválido")

@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse: return FileResponse(BASE_DIR / "static" / "dashboard.html", headers={"Cache-Control": "no-store"})
@app.get("/salud")
async def salud() -> dict[str, Any]: return {"estado": "ok", "hora": ahora(), "cola": estado.cola.qsize()}
@app.get("/eventos")
async def listar_eventos() -> list[dict[str, Any]]: return list(estado.eventos)
@app.get("/resumen")
async def obtener_resumen() -> dict[str, int]: return resumen()
@app.post("/evento", status_code=202)
async def recibir_evento(evento: EventoEntrada, x_esp32_token: str | None = Header(default=None)) -> dict[str, str]:
    verificar_token(x_esp32_token)
    firma = (evento.tipo, evento.mac_origen, evento.bssid_objetivo)
    instante = asyncio.get_running_loop().time()
    anterior = estado.ultimos_eventos.get(firma)
    if anterior is not None and instante - anterior < VENTANA_DUPLICADOS_SEGUNDOS:
        return {"estado": "duplicado_omitido", "id": ""}
    estado.ultimos_eventos[firma] = instante
    registro = {"id": str(uuid4()), "estado": "pendiente", "nivel": "PENDIENTE", "recibido_en": ahora(), "evento": evento.model_dump()}
    estado.eventos.appendleft(registro)
    await estado.cola.put(registro)
    await estado.publicar({"tipo": "evento_recibido", "evento": registro})
    return {"estado": "aceptado", "id": registro["id"]}
@app.websocket("/ws")
async def websocket_dashboard(websocket: WebSocket) -> None:
    await websocket.accept(); estado.clientes.add(websocket)
    await websocket.send_json({"tipo": "estado_inicial", "eventos": list(estado.eventos)})
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect: estado.clientes.discard(websocket)
