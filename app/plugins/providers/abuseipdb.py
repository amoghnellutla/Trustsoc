"""AbuseIPDB v2 enrichment plugin — IP reputation."""

import logging
from typing import Any, Dict, Optional

import requests

from app.plugins.base import BaseEnrichmentPlugin
from app.config import settings

logger = logging.getLogger(__name__)


class AbuseIPDBPlugin(BaseEnrichmentPlugin):
    name = "abuseipdb"
    supported_types = ["ip"]
    cost_per_call_usd = 0.0  # Free tier: 1,000/day

    def enrich(self, ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        if ioc_type != "ip":
            return None
        api_key = settings.ABUSEIPDB_API_KEY
        if not api_key:
            return None

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ioc_value, "maxAgeInDays": 90},
                timeout=10,
            )
            if resp.status_code == 404:
                return {"found": False, "provider": self.name}
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {
                "found": True,
                "provider": self.name,
                "abuse_confidence_score": score,
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "last_reported_at": data.get("lastReportedAt"),
                "is_tor": data.get("isTor", False),
                "summary": f"{score}% abuse confidence",
            }
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB error for %s: %s", ioc_value, exc)
            return None
