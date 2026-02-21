"""
TrustSOC – Evidence-Based SOC Automation Platform
Main FastAPI application entry point.
"""
import time
import uuid
import logging
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import settings
from app.database import engine, Base
from app.routers import alerts, incidents, cases


# ============================================================================
# STRUCTURED JSON LOGGING
# ============================================================================

class _JsonFormatter(logging.Formatter):
    """Emit every log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def _setup_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, settings.LOG_LEVEL, logging.INFO))


_setup_logging()
logger = logging.getLogger("trustsoc")


# ============================================================================
# RATE LIMITER (slowapi)
# NOTE: default_limits only take effect when SlowAPIMiddleware is added.
# ============================================================================

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ============================================================================
# STARTUP / SHUTDOWN
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("TrustSOC starting")
    logger.info("environment=%s auto_block=%s", settings.ENVIRONMENT, settings.AUTO_BLOCK_ENABLED)
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables ready")
    except Exception as exc:
        logger.error("Database init failed: %s", exc, exc_info=True)
    yield
    logger.info("TrustSOC shutting down")


# ============================================================================
# APPLICATION
# ============================================================================

app = FastAPI(
    title="TrustSOC API",
    description="""
**Evidence-Based SOC Automation Platform**

TrustSOC automates security alert triage with:
- Intelligent risk scoring with confidence
- Threat intelligence enrichment (VT · AbuseIPDB · OTX)
- Alert correlation into incidents
- Safe, time-limited automated responses with rollback
- Tamper-evident evidence bundles
- Policy-based, explainable decisions
- Analyst feedback loop for continuous improvement

Every decision is auditable and reproducible.
""",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Attach limiter + middleware (THIS is what makes rate limiting work)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS – tighten allowed_origins when you deploy a real frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# MIDDLEWARES
# ============================================================================

@app.middleware("http")
async def request_id_and_timing(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id

    start = time.perf_counter()
    response = await call_next(request)
    elapsed = round((time.perf_counter() - start) * 1000, 2)

    response.headers["X-Request-ID"] = req_id
    response.headers["X-Process-Time-Ms"] = str(elapsed)

    logger.info(
        "request completed method=%s path=%s status=%s duration_ms=%s request_id=%s",
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
        req_id,
    )
    return response


# ============================================================================
# EXCEPTION HANDLERS
# ============================================================================

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", "unknown")
    logger.warning("Validation error request_id=%s errors=%s", req_id, exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": "Validation Error", "details": exc.errors(), "request_id": req_id},
        headers={"X-Request-ID": req_id},
    )


@app.exception_handler(Exception)
async def general_error_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "unknown")
    logger.error("Unhandled exception request_id=%s: %s", req_id, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal Server Error", "request_id": req_id},
        headers={"X-Request-ID": req_id},
    )


# ============================================================================
# ROUTERS
# ============================================================================

app.include_router(alerts.router,    prefix="/api/v1/alerts",    tags=["Alerts"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents"])
app.include_router(cases.router,     prefix="/api/v1/cases",     tags=["Cases"])


# ============================================================================
# SYSTEM ENDPOINTS
# ============================================================================

@app.get("/", tags=["System"], summary="Service info")
def root():
    return {
        "service": "TrustSOC API",
        "version": "0.1.0",
        "status": "running",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs",
    }


@app.get("/health", tags=["System"], summary="Health check")
def health_check():
    return {"status": "healthy", "timestamp": time.time()}


@app.get("/api/v1/stats", tags=["System"], summary="System statistics")
def get_stats():
    """Counts of alerts and incidents in the last 24 hours."""
    from app.database import SessionLocal
    from app.models import Alert, Incident
    from datetime import datetime, timedelta

    db = SessionLocal()
    try:
        since = datetime.utcnow() - timedelta(days=1)

        total_alerts = db.query(Alert).count()
        alerts_24h = db.query(Alert).filter(Alert.created_at >= since).count()

        total_incidents = db.query(Incident).count()
        incidents_24h = db.query(Incident).filter(Incident.created_at >= since).count()

        high_risk = (
            db.query(Alert)
            .filter(
                Alert.risk_score >= settings.HIGH_RISK_THRESHOLD,
                Alert.status.in_(["new", "processing"]),
            )
            .count()
        )

        return {
            "total_alerts": total_alerts,
            "alerts_24h": alerts_24h,
            "total_incidents": total_incidents,
            "incidents_24h": incidents_24h,
            "high_risk_open": high_risk,
            "system_healthy": True,
        }
    finally:
        db.close()