"""Redis cache layer with in-memory fallback when Redis is not running."""
import json
import time
from typing import Any, Dict, Optional

from backend.app.config import get_settings

settings = get_settings()
_redis: Optional[Any] = None
_use_memory = False
_memory_store: Dict[str, tuple[Any, float]] = {}
_memory_pubsub: Dict[str, list] = {}


class _MemoryRedis:
    """Minimal async-compatible Redis substitute for local dev without Docker."""

    async def get(self, key: str):
        item = _memory_store.get(key)
        if item and item[1] > time.time():
            return item[0]
        return None

    async def setex(self, key: str, ttl: int, value: str):
        _memory_store[key] = (value, time.time() + ttl)

    async def delete(self, key: str):
        _memory_store.pop(key, None)

    async def publish(self, channel: str, message: str):
        _memory_pubsub.setdefault(channel, []).append(message)

    async def incr(self, key: str):
        val = await self.get(key)
        count = int(val) + 1 if val else 1
        await self.setex(key, 60, str(count))
        return count

    async def expire(self, key: str, ttl: int):
        pass

    def pubsub(self):
        return _MemoryPubSub()


class _MemoryPubSub:
    async def subscribe(self, *channels):
        self._channels = channels

    async def listen(self):
        while True:
            await asyncio_sleep(1)
            yield {"type": "subscribe"}

    async def unsubscribe(self):
        pass


async def asyncio_sleep(sec: float):
    import asyncio
    await asyncio.sleep(sec)


async def get_redis():
    global _redis, _use_memory
    if _redis is not None:
        return _redis
    if _use_memory:
        return _MemoryRedis()
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await client.ping()
        _redis = client
        return _redis
    except Exception:
        _use_memory = True
        return _MemoryRedis()


async def cache_get(key: str) -> Optional[Any]:
    r = await get_redis()
    val = await r.get(key)
    if val:
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return val
    return None


async def cache_set(key: str, value: Any, ttl: int = 300) -> None:
    r = await get_redis()
    await r.setex(key, ttl, json.dumps(value, default=str))


async def cache_delete(key: str) -> None:
    r = await get_redis()
    await r.delete(key)


async def publish_event(channel: str, data: dict) -> None:
    r = await get_redis()
    await r.publish(channel, json.dumps(data, default=str))


async def increment_rate_limit(key: str, limit: int = 100, window: int = 60) -> bool:
    r = await get_redis()
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, window)
    return count <= limit
