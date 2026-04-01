"""
Application configuration from environment variables.
Compatible with Pydantic v2.

Only DATABASE_URL and API_KEY are required.
All external API keys are optional — TrustSOC degrades gracefully without them.
"""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import ConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables
    """

    # =========================
    # Database (required)
    # =========================
    DATABASE_URL: str

    # =========================
    # API Settings (required)
    # =========================
    API_KEY: str
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # =========================
    # External APIs (all optional — system degrades gracefully)
    # =========================
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None  # For LLM investigation narratives

    # =========================
    # Offline / Air-Gapped Mode
    # =========================
    OFFLINE_MODE: bool = False  # True = skip ALL external API calls; use mock data only

    # =========================
    # Enrichment Settings
    # =========================
    ENRICHMENT_BUDGET_PER_ALERT_USD: float = 0.10   # Max API cost per alert
    ENRICHMENT_CACHE_TTL_SECONDS: int = 3600         # 1 hour cache for IOC lookups
    TRUSTSOC_PLUGIN_DIR: Optional[str] = None        # Custom plugin directory path

    # =========================
    # Rate Limiting
    # =========================
    MAX_ALERTS_PER_MINUTE: int = 100
    MAX_BLOCKS_PER_HOUR: int = 50

    # =========================
    # Safety Settings
    # =========================
    AUTO_BLOCK_ENABLED: bool = True
    AUTO_BLOCK_DURATION_MINUTES: int = 15
    CRITICAL_ASSET_MIN_SCORE: int = 8

    # =========================
    # Risk Thresholds
    # =========================
    HIGH_RISK_THRESHOLD: int = 70
    MEDIUM_RISK_THRESHOLD: int = 40
    LOW_RISK_THRESHOLD: int = 0

    # =========================
    # Confidence Thresholds
    # =========================
    HIGH_CONFIDENCE_THRESHOLD: float = 0.8
    MEDIUM_CONFIDENCE_THRESHOLD: float = 0.5

    # =========================
    # Correlation Settings
    # =========================
    CORRELATION_TIME_WINDOW_MINUTES: int = 15
    MIN_ALERTS_FOR_INCIDENT: int = 3

    # =========================
    # Pydantic v2 Config
    # =========================
    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=True,
    )


# Global settings instance
settings = Settings()