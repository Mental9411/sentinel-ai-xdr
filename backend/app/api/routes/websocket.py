"""WebSocket real-time streaming."""
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.core.redis_cache import get_redis

router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def alerts_stream(websocket: WebSocket):
    await manager.connect(websocket)
    redis = await get_redis()
    pubsub = redis.pubsub()
    await pubsub.subscribe("sentinel:alerts:stream", "sentinel:events:stream")
    try:
        async def listener():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = json.loads(message["data"])
                    await manager.broadcast({"channel": message["channel"], "data": data})

        task = asyncio.create_task(listener())
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        task.cancel()
    finally:
        await pubsub.unsubscribe()
