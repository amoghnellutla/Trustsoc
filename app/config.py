"""
Application configuration from environment variables.
Compatible with Pydantic v2.
"""

from pydantic_settings import BaseSettings
from pydantic import ConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables
    """

    # =========================
    # Database
    # =========================
    DATABASE_URL: str

    # =========================
    # API Settings
    # =========================
    API_KEY: str
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # =========================
    # External APIs
    # =========================
    VIRUSTOTAL_API_KEY: str
    ABUSEIPDB_API_KEY: str
    OTX_API_KEY: str

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