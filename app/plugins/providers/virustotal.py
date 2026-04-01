"""VirusTotal v3 enrichment plugin — file hashes, IPs, domains, URLs."""

import base64
import logging
from typing import Any, Dict, Optional

import requests

from app.plugins.base import BaseEnrichmentPlugin
from app.config import settings

logger = logging.getLogger(__name__)


class VirusTotalPlugin(BaseEnrichmentPlugin):
    name = "virustotal"
    supported_types = ["hash", "ip", "domain", "url"]
    cost_per_call_usd = 0.0  # Free tier: 4 req/min

    def enrich(self, ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        api_key = settings.VIRUSTOTAL_API_KEY
        if not api_key:
            return None

        headers = {"x-apikey": api_key}
        try:
            if ioc_type == "url":
                url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers, timeout=10,
                )
            else:
                path_map = {
                    "ip": f"ip_addresses/{ioc_value}",
                    "domain": f"domains/{ioc_value}",
                    "hash": f"files/{ioc_value}",
                }
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/{path_map[ioc_type]}",
                    headers=headers, timeout=10,
                )

            if resp.status_code == 404:
                return {"found": False, "provider": self.name}
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            return {
                "found": True,
                "provider": self.name,
                "malicious_detections": malicious,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}" if total else "0/0",
                "reputation": attrs.get("reputation", 0),
                "tags": attrs.get("tags", []),
                "summary": f"{malicious}/{total} engines flagged",
            }
        except requests.RequestException as exc:
            logger.warning("VirusTotal error for %s: %s", ioc_value, exc)
            return None
