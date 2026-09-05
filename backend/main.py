import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from .api.alerts import router as alerts_router
from .api.flows import router as flows_router
from .api.status import router as status_router
from .database import init_database, store_alert, store_flow
from .schemas import Flow
from .detector_bridge import detect_flow

app = FastAPI(
    title="ARGUS-ONE Backend",
    description="Backend API for ARGUS-ONE threat detection",
    version="1.0.0"
)
app.include_router(alerts_router)
app.include_router(flows_router)
app.include_router(status_router)


class AlertConnectionManager:
    def __init__(self):
        self.connections: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.connections.add(websocket)
        self.loop = asyncio.get_running_loop()

    def disconnect(self, websocket: WebSocket):
        self.connections.discard(websocket)

    async def broadcast(self, alert: dict):
        stale = []
        for websocket in self.connections:
            try:
                await websocket.send_json(alert)
            except (WebSocketDisconnect, RuntimeError):
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(websocket)

    def publish(self, alert: dict):
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self.broadcast(alert),
                self.loop,
            )


alert_connections = AlertConnectionManager()


@app.on_event("startup")
def startup():
    init_database()


@app.get("/")
def root():
    return {
        "system": "ARGUS-ONE",
        "status": "running"
    }


@app.post("/api/flows")
def receive_flow(flow: Flow):
    flow_data = flow.model_dump()

    store_flow(flow_data)
    result = detect_flow(flow)
    for alert in result:
        store_alert(alert)
        alert_connections.publish(alert)

    return {
        "success": True,
        "alerts": result
    }


@app.websocket("/ws/alerts")
async def live_alerts(websocket: WebSocket):
    await alert_connections.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        alert_connections.disconnect(websocket)