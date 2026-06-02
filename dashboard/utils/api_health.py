"""Resolve a reachable API base URL for the dashboard."""
import os
from typing import List, Optional, Tuple

import httpx

DEFAULT_CANDIDATES = (
    "http://127.0.0.1:8000",
    "http://localhost:8000",
)


def candidate_api_urls() -> List[str]:
    urls: List[str] = []
    env_url = (os.getenv("API_BASE_URL") or "").strip().rstrip("/")
    if env_url:
        urls.append(env_url)
    for u in DEFAULT_CANDIDATES:
        if u not in urls:
            urls.append(u)
    return urls


def probe_api(base_url: str, timeout: float = 8.0) -> Tuple[bool, str, Optional[dict]]:
    """Return (ok, message, health_json)."""
    url = base_url.rstrip("/")
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.get(f"{url}/health")
            if r.status_code != 200:
                return False, f"HTTP {r.status_code}", None
            data = r.json()
            status = data.get("status", "unknown")
            if status in ("healthy", "degraded"):
                return True, status, data
            return False, f"Unexpected status: {status}", data
    except httpx.ConnectError:
        return False, "Connection refused - API not running on this address", None
    except httpx.TimeoutException:
        return False, "Timed out waiting for API", None
    except Exception as exc:
        return False, str(exc), None


def discover_api_url() -> Tuple[Optional[str], str]:
    """Try candidate URLs. Returns (working_url, diagnostic_message)."""
    tried = []
    for base in candidate_api_urls():
        ok, msg, _ = probe_api(base)
        tried.append(f"{base} -> {msg}")
        if ok:
            return base, f"Connected ({msg})"
    return None, "\n".join(tried)
