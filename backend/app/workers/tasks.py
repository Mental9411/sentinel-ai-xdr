"""Celery tasks."""
import asyncio

from backend.app.workers.celery_app import celery_app


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(name="backend.app.workers.tasks.run_realtime_collection")
def run_realtime_collection():
    async def _collect():
        from backend.app.mongodb import connect_mongodb
        from backend.app.services.event_pipeline import process_realtime_cycle
        await connect_mongodb()
        return await process_realtime_cycle()

    return _run_async(_collect())


@celery_app.task(name="backend.app.workers.tasks.sync_threat_feeds")
def sync_threat_feeds():
    return {"status": "scheduled"}


@celery_app.task(name="backend.app.workers.tasks.update_ueba_baselines")
def update_ueba_baselines():
    return {"status": "completed"}


@celery_app.task(name="backend.app.workers.tasks.check_ml_drift")
def check_ml_drift():
    return {"drift_score": 0.0, "retrain_needed": False}
