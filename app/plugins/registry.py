"""
PluginRegistry — discovers and manages enrichment plugins.

Load order:
  1. Built-in providers (app/plugins/providers/*.py) — always loaded
  2. Community plugins from TRUSTSOC_PLUGIN_DIR — loaded if set

Plugins are stored in order; first match wins within each IOC type.
The registry is a module-level singleton initialized at app startup.
"""

import importlib.util
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Type

from app.plugins.base import BaseEnrichmentPlugin

logger = logging.getLogger(__name__)

_BUILTIN_PROVIDERS_DIR = Path(__file__).parent / "providers"


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: List[BaseEnrichmentPlugin] = []

    def register(self, plugin: BaseEnrichmentPlugin) -> None:
        self._plugins.append(plugin)
        logger.info("Plugin registered: %s (types=%s)", plugin.name, plugin.supported_types)

    def get_providers_for(self, ioc_type: str) -> List[BaseEnrichmentPlugin]:
        """Return all plugins that support the given IOC type, in priority order."""
        return [p for p in self._plugins if p.supports(ioc_type)]

    @property
    def all_plugins(self) -> List[BaseEnrichmentPlugin]:
        return list(self._plugins)

    def load_builtin_providers(self) -> None:
        """Import every module in app/plugins/providers/ and register plugin classes."""
        for py_file in sorted(_BUILTIN_PROVIDERS_DIR.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = f"app.plugins.providers.{py_file.stem}"
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    obj = getattr(module, attr_name)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, BaseEnrichmentPlugin)
                        and obj is not BaseEnrichmentPlugin
                        and not getattr(obj, "__abstractmethods__", None)
                    ):
                        self.register(obj())
            except Exception as exc:
                logger.error("Failed to load builtin plugin %s: %s", py_file.name, exc)

    def load_community_plugins(self, plugin_dir: Optional[str]) -> None:
        """Load plugins from TRUSTSOC_PLUGIN_DIR (user-supplied directory)."""
        if not plugin_dir:
            return
        path = Path(plugin_dir)
        if not path.is_dir():
            logger.warning("TRUSTSOC_PLUGIN_DIR %s does not exist — skipping", plugin_dir)
            return
        for py_file in sorted(path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            if not spec or not spec.loader:
                continue
            try:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)  # type: ignore[union-attr]
                for attr_name in dir(module):
                    obj = getattr(module, attr_name)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, BaseEnrichmentPlugin)
                        and obj is not BaseEnrichmentPlugin
                        and not getattr(obj, "__abstractmethods__", None)
                    ):
                        self.register(obj())
                        logger.info("Community plugin loaded: %s from %s", obj.__name__, py_file)
            except Exception as exc:
                logger.error("Failed to load community plugin %s: %s", py_file.name, exc)

    def summary(self) -> Dict:
        return {
            "total_plugins": len(self._plugins),
            "plugins": [
                {"name": p.name, "types": p.supported_types, "cost_per_call": p.cost_per_call_usd}
                for p in self._plugins
            ],
        }


# Module-level singleton — populated during app lifespan startup
registry = PluginRegistry()


def initialize_plugins(plugin_dir: Optional[str] = None) -> PluginRegistry:
    """Called once at app startup. Returns the populated registry."""
    registry.load_builtin_providers()
    registry.load_community_plugins(plugin_dir)
    logger.info("Plugin registry ready: %d plugins loaded", len(registry.all_plugins))
    return registry
