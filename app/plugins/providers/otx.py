"""AlienVault OTX enrichment plugin — IPs, domains, file hashes."""

import logging
from typing import Any, Dict, Optional

import requests

from app.plugins.base import BaseEnrichmentPlugin
from app.config import settings

logger = logging.getLogger(__name__)


class OTXPlugin(BaseEnrichmentPlugin):
    name = "otx"
    supported_types = ["ip", "domain", "hash"]
    cost_per_call_usd = 0.0  # Unlimited free tier

    _SECTION_MAP = {
        "ip": ("IPv4", "general"),
        "domain": ("domain", "general"),
        "hash": ("file", "general"),
    }

    def enrich(self, ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        api_key = settings.OTX_API_KEY
        if not api_key:
            return None

        indicator_type, section = self._SECTION_MAP.get(ioc_type, (None, None))
        if not indicator_type:
            return None

        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{ioc_value}/{section}",
                headers={"X-OTX-API-KEY": api_key},
                timeout=10,
            )
            if resp.status_code == 404:
                return {"found": False, "provider": self.name}
            resp.raise_for_status()
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            families = [
                p.get("name")
                for p in data.get("pulse_info", {}).get("pulses", [])[:5]
            ]
            return {
                "found": True,
                "provider": self.name,
                "pulse_count": pulse_count,
                "reputation": data.get("reputation", 0),
                "country": data.get("country_name"),
                "asn": data.get("asn"),
                "malware_families": families,
                "summary": f"{pulse_count} threat pulses",
            }
        except requests.RequestException as exc:
            logger.warning("OTX error for %s: %s", ioc_value, exc)
            return None
