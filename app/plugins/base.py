"""
BaseEnrichmentPlugin — abstract contract every plugin must implement.

To create a community plugin:
1. Subclass BaseEnrichmentPlugin
2. Set `name`, `supported_types`, `cost_per_call_usd`
3. Implement `enrich(ioc_value, ioc_type) -> Optional[Dict]`
4. Drop the file in TRUSTSOC_PLUGIN_DIR (default: ~/.trustsoc/plugins/)

Return None to signal "skip this IOC" (no API key, unsupported type, network error).
Return a dict with at least {"found": bool, "provider": self.name}.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseEnrichmentPlugin(ABC):
    """Abstract base class for all TrustSOC enrichment plugins."""

    # ── Required class attributes ───────────────────────────────────────────
    name: str                          # Unique provider identifier (e.g. "virustotal")
    supported_types: List[str]         # IOC types: "ip", "domain", "hash", "url"
    cost_per_call_usd: float = 0.0    # USD cost per API call (for budget tracking)

    @abstractmethod
    def enrich(self, ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """
        Enrich a single IOC.

        Args:
            ioc_value: The IOC to look up (e.g. "185.1.2.3", "malware.exe")
            ioc_type:  One of "ip", "domain", "hash", "url"

        Returns:
            dict with at least {"found": bool, "provider": self.name}
            None if this provider cannot handle the request (skip silently)
        """

    def supports(self, ioc_type: str) -> bool:
        """Returns True if this plugin handles the given IOC type."""
        return ioc_type in self.supported_types

    def __repr__(self) -> str:
        return f"<Plugin:{self.name} types={self.supported_types}>"
