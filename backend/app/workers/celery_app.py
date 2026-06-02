"""Celery background workers for real-time collection."""
from celery import Celery
from celery.schedules import crontab

from backend.app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "sentinel",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "realtime-collection": {
            "task": "backend.app.workers.tasks.run_realtime_collection",
            "schedule": 30.0,
        },
        "threat-intel-sync": {
            "task": "backend.app.workers.tasks.sync_threat_feeds",
            "schedule": crontab(hour="*/6"),
        },
        "ueba-baseline-update": {
            "task": "backend.app.workers.tasks.update_ueba_baselines",
            "schedule": crontab(minute="*/15"),
        },
        "ml-drift-check": {
            "task": "backend.app.workers.tasks.check_ml_drift",
            "schedule": crontab(hour="*/12"),
        },
    },
)

celery_app.autodiscover_tasks(["backend.app.workers"])
