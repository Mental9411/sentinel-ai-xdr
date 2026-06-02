"""API client for dashboard — shared HTTP session, safe timeouts."""
from typing import Any, Dict, List, Optional

import httpx
import streamlit as st

_DEFAULT_TIMEOUT = httpx.Timeout(5.0, connect=3.0)
_SLOW_TIMEOUT = httpx.Timeout(30.0, connect=5.0)
_COLLECT_TIMEOUT = httpx.Timeout(90.0, connect=5.0)
_DISCOVER_TIMEOUT = httpx.Timeout(120.0, connect=5.0)


class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.token = st.session_state.get("token")
        self._client = httpx.Client(timeout=_DEFAULT_TIMEOUT, follow_redirects=True)

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        token = st.session_state.get("token") or self.token
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def _error_detail(self, r: httpx.Response) -> str:
        try:
            data = r.json()
            detail = data.get("detail", r.text)
            if isinstance(detail, list):
                msgs = []
                for item in detail:
                    if isinstance(item, dict):
                        loc = ".".join(str(x) for x in item.get("loc", []))
                        msgs.append(f"{loc}: {item.get('msg', '')}")
                    else:
                        msgs.append(str(item))
                return "; ".join(msgs) if msgs else str(detail)
            if isinstance(detail, dict):
                return str(detail)
            return str(detail)
        except Exception:
            return r.text or f"HTTP {r.status_code}"

    def _get(self, path: str, params: Optional[Dict] = None, timeout: httpx.Timeout = _DEFAULT_TIMEOUT) -> httpx.Response:
        return self._client.get(
            f"{self.base_url}{path}",
            headers=self._headers(),
            params=params,
            timeout=timeout,
        )

    def _post(self, path: str, json: Optional[Dict] = None, timeout: httpx.Timeout = _DEFAULT_TIMEOUT) -> httpx.Response:
        return self._client.post(
            f"{self.base_url}{path}",
            headers=self._headers(),
            json=json,
            timeout=timeout,
        )

    def health(self) -> Dict:
        r = self._client.get(f"{self.base_url}/health", timeout=_DEFAULT_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if data.get("status") not in ("healthy", "degraded"):
            raise httpx.HTTPError(f"API status: {data.get('status')}")
        return data

    def reconnect(self) -> bool:
        from dashboard.utils.api_health import discover_api_url

        url, _ = discover_api_url()
        if url:
            self.base_url = url.rstrip("/")
            return True
        return False

    def login(self, email: str, password: str, mfa_token: Optional[str] = None) -> Dict:
        email = (email or "").strip()
        if not email or "@" not in email:
            raise ValueError("Please enter a valid email address")
        if not password:
            raise ValueError("Please enter your password")
        r = self._post(
            "/api/v1/auth/login",
            json={"email": email, "password": password, "mfa_token": mfa_token},
            timeout=_SLOW_TIMEOUT,
        )
        if r.status_code != 200:
            raise ValueError(self._error_detail(r))
        return r.json()

    def register(self, data: Dict) -> Dict:
        r = self._post("/api/v1/auth/register", json=data, timeout=_SLOW_TIMEOUT)
        if r.status_code not in (200, 201):
            raise ValueError(self._error_detail(r))
        return r.json()

    def get_me(self) -> Dict:
        r = self._get("/api/v1/auth/me")
        if r.status_code != 200:
            raise ValueError(self._error_detail(r))
        return r.json()

    def get_alerts(
        self,
        limit: int = 100,
        detection_engine: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[Dict]:
        params: Dict[str, Any] = {"limit": limit}
        if detection_engine:
            params["detection_engine"] = detection_engine
        if source:
            params["source"] = source
        try:
            r = self._get("/api/v1/alerts/", params=params, timeout=_SLOW_TIMEOUT)
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return []

    def get_ids_summary(self) -> Dict:
        try:
            r = self._get("/api/v1/alerts/ids/summary")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {}

    def get_ips_status(self) -> Dict:
        try:
            r = self._get("/api/v1/ips/status")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {}

    def set_ips_mode(self, mode: str) -> Dict:
        r = self._post("/api/v1/ips/mode", json={"mode": mode})
        if r.status_code == 200:
            return r.json()
        raise ValueError(self._error_detail(r))

    def request_ips_block(self, source_ip: Optional[str] = None, reason: str = "") -> Dict:
        r = self._post(
            "/api/v1/ips/block-request",
            json={"source_ip": source_ip, "reason": reason or "Dashboard block request"},
        )
        if r.status_code == 200:
            return r.json()
        raise ValueError(self._error_detail(r))

    def get_cloud_status(self) -> Dict:
        try:
            r = self._get("/api/v1/dashboard/cloud-status")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {}

    def get_stats(self) -> Dict:
        nav = st.session_state.get("live_nav")
        if nav:
            return nav
        try:
            r = self._get("/api/v1/dashboard/stats")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {}

    def get_nav_summary(self) -> Dict:
        try:
            r = self._get("/api/v1/dashboard/nav-summary")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return self.get_stats()

    def get_endpoint_live(self) -> Dict:
        cached = st.session_state.get("live_endpoint")
        if cached:
            return cached
        try:
            r = self._get("/api/v1/dashboard/endpoint", timeout=httpx.Timeout(8.0, connect=3.0))
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {}

    def get_events(self, limit: int = 50) -> List[Dict]:
        try:
            r = self._get("/api/v1/dashboard/events", params={"limit": limit})
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return []

    def trigger_collect(self) -> Dict:
        try:
            r = self._post("/api/v1/dashboard/collect", timeout=_COLLECT_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            return {"error": self._error_detail(r)}
        except httpx.HTTPError as e:
            return {"error": str(e)}

    def discover_network(self, subnet: Optional[str] = None) -> Dict:
        r = self._post(
            "/api/v1/network/discover",
            json={"subnet": subnet, "scan_ports": True},
            timeout=_DISCOVER_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()

    def get_devices(self) -> List[Dict]:
        try:
            r = self._get("/api/v1/network/devices")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return []

    def get_topology(self) -> Dict:
        try:
            r = self._get("/api/v1/network/topology")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {}

    def enrich_ioc(self, value: str, ioc_type: Optional[str] = None) -> Dict:
        try:
            r = self._post(
                "/api/v1/threat-intel/enrich",
                json={"value": value, "ioc_type": ioc_type},
                timeout=_SLOW_TIMEOUT,
            )
            if r.status_code == 200:
                return r.json()
            return {"error": self._error_detail(r)}
        except httpx.HTTPError as e:
            return {"error": str(e)}

    def get_threat_intel_summary(self) -> Dict:
        try:
            r = self._get("/api/v1/threat-intel/summary")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {}

    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        try:
            r = self._get("/api/v1/audit/", params={"limit": limit})
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return []

    def get_compliance(self) -> List[Dict]:
        try:
            r = self._get("/api/v1/compliance/frameworks")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return []

    def get_local_subnet(self) -> Dict:
        r = self._get("/api/v1/network/local-subnet")
        r.raise_for_status()
        return r.json()

    def get_pentest_detections(self) -> List[Dict]:
        try:
            r = self._get("/api/v1/pentest/detections")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return []

    def get_pentest_summary(self) -> Dict:
        try:
            r = self._get("/api/v1/pentest/summary")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {}

    def run_pentest_collection(self) -> Dict:
        try:
            r = self._post("/api/v1/pentest/run-collection", timeout=_COLLECT_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            return {"error": self._error_detail(r)}
        except httpx.HTTPError as e:
            return {"error": str(e)}

    def get_packets(self, limit: int = 50) -> List[Dict]:
        try:
            r = self._get("/api/v1/network/capture/packets", params={"limit": limit})
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return []

    def start_capture(self) -> Dict:
        try:
            r = self._post("/api/v1/network/capture/start")
            if r.status_code == 200:
                return r.json()
            return {"error": self._error_detail(r), "status_code": r.status_code}
        except httpx.HTTPError as e:
            return {"error": str(e)}

    def get_capture_status(self) -> Dict:
        try:
            r = self._get("/api/v1/network/capture/status")
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        return {"capturing": False, "recent_packets": 0}

    def invite_user(self, email: str, role: str) -> Dict:
        r = self._post("/api/v1/auth/invite", json={"email": email, "role": role})
        r.raise_for_status()
        return r.json()

    def create_user(self, data: Dict) -> Dict:
        r = self._post("/api/v1/auth/users", json=data)
        r.raise_for_status()
        return r.json()
