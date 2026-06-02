"""Threat Intelligence integrations with IOC enrichment and caching."""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from backend.app.config import get_settings
from backend.app.core.redis_cache import cache_get, cache_set

settings = get_settings()


class ThreatIntelService:
    """IOC enrichment from MISP, OTX, AbuseIPDB, VirusTotal, GreyNoise, etc."""

    async def enrich_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        cache_key = f"sentinel:ioc:{ioc_type}:{value}"
        cached = await cache_get(cache_key)
        if cached:
            return cached
        result = {
            "ioc_type": ioc_type,
            "value": value,
            "reputation_score": 0.0,
            "sources": [],
            "tags": [],
            "threat_actor": None,
            "enrichment_data": {},
        }
        if ioc_type == "ip":
            if settings.abuseipdb_api_key:
                abuse = await self._abuseipdb_lookup(value)
                if abuse:
                    result["sources"].append("abuseipdb")
                    result["reputation_score"] = max(result["reputation_score"], abuse.get("score", 0))
                    result["enrichment_data"]["abuseipdb"] = abuse
            if settings.greynoise_api_key:
                gn = await self._greynoise_lookup(value)
                if gn:
                    result["sources"].append("greynoise")
                    result["enrichment_data"]["greynoise"] = gn
        if settings.otx_api_key and ioc_type in ("ip", "domain", "hash_sha256"):
            otx = await self._otx_lookup(ioc_type, value)
            if otx:
                result["sources"].append("otx")
                result["tags"].extend(otx.get("tags", []))
                result["enrichment_data"]["otx"] = otx
        if settings.virustotal_api_key and ioc_type in ("ip", "domain", "hash_sha256"):
            vt = await self._virustotal_lookup(ioc_type, value)
            if vt:
                result["sources"].append("virustotal")
                result["reputation_score"] = max(result["reputation_score"], vt.get("score", 0))
                result["enrichment_data"]["virustotal"] = vt
        await cache_set(cache_key, result, ttl=86400)
        return result

    async def _abuseipdb_lookup(self, ip: str) -> Optional[Dict]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    return {"score": data.get("abuseConfidenceScore", 0) / 100, "reports": data.get("totalReports", 0)}
        except Exception:
            pass
        return None

    async def _greynoise_lookup(self, ip: str) -> Optional[Dict]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    headers={"key": settings.greynoise_api_key},
                )
                if r.status_code == 200:
                    return r.json()
        except Exception:
            pass
        return None

    async def _otx_lookup(self, ioc_type: str, value: str) -> Optional[Dict]:
        section = {"ip": "IPv4", "domain": "domain", "hash_sha256": "file"}.get(ioc_type, "general")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
                    headers={"X-OTX-API-KEY": settings.otx_api_key},
                )
                if r.status_code == 200:
                    data = r.json()
                    return {"tags": [p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])]}
        except Exception:
            pass
        return None

    async def _virustotal_lookup(self, ioc_type: str, value: str) -> Optional[Dict]:
        endpoints = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
            "hash_sha256": f"https://www.virustotal.com/api/v3/files/{value}",
        }
        url = endpoints.get(ioc_type)
        if not url:
            return None
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers={"x-apikey": settings.virustotal_api_key})
                if r.status_code == 200:
                    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) or 1
                    return {"score": malicious / total, "stats": stats}
        except Exception:
            pass
        return None

    async def correlate_iocs(self, iocs: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        results = []
        for ioc in iocs:
            enriched = await self.enrich_ioc(ioc["type"], ioc["value"])
            if enriched["reputation_score"] > 0.5 or enriched["tags"]:
                results.append(enriched)
        return results
