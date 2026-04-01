"""
Threat intelligence enrichment service.

Enriches alerts by querying external threat intel providers for each IOC.
Providers are loaded via the plugin registry (app/plugins/registry.py).

Designed for free-tier API limits:
  - Graceful degradation: missing API keys skip the provider, never crash
  - Cost tracking: every API call records its USD cost
  - Budget cap: stops enriching when per-alert budget is exceeded
  - Community plugins: drop a .py file in TRUSTSOC_PLUGIN_DIR

Pipeline order per alert:
  1. Extract IOCs from normalized_alert
  2. For each IOC, query available plugins via registry
  3. Store Enrichment records with results + cost
  4. Calculate and update alert risk_score + confidence_score
  5. Create evidence record for audit trail
  6. Update alert status to "enriched"
"""

import logging
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Tuple
from uuid import UUID

from sqlalchemy.orm import Session

from app import models
from app.config import settings
from app.plugins.registry import registry
from app.utils.evidence import create_evidence
from app.utils.helpers import is_private_ip

logger = logging.getLogger(__name__)

_MOCK_RESULT = {
    "mock": True,
    "note": "Set VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY / OTX_API_KEY for real threat intel",
    "simulated_risk": "medium",
}


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _calculate_risk_score(
    enrichments: List[Dict[str, Any]], normalized_alert: Dict
) -> Tuple[int, float, str]:
    score = 0
    confidence_votes = []
    factors = []

    severity_base = {"critical": 60, "high": 45, "medium": 25, "low": 10}
    severity = normalized_alert.get("severity", "medium")
    base = severity_base.get(severity, 25)
    score += base
    factors.append(f"Alert severity '{severity}' (+{base})")

    for enrichment in enrichments:
        result = enrichment.get("result", {})
        provider = result.get("provider", "")

        if result.get("mock"):
            continue

        if provider == "virustotal" and result.get("found"):
            malicious = result.get("malicious_detections", 0)
            total = result.get("total_engines", 1)
            if malicious > 0:
                vt_score = min(35, int((malicious / max(total, 1)) * 35))
                score += vt_score
                confidence_votes.append(0.9)
                factors.append(f"VirusTotal: {malicious}/{total} engines flagged (+{vt_score})")
            else:
                confidence_votes.append(0.7)
                factors.append("VirusTotal: clean (0 detections)")

        elif provider == "abuseipdb" and result.get("found"):
            abuse_score = result.get("abuse_confidence_score", 0)
            if abuse_score > 0:
                ip_score = min(25, int(abuse_score * 0.25))
                score += ip_score
                confidence_votes.append(0.85)
                factors.append(f"AbuseIPDB: {abuse_score}% confidence (+{ip_score})")
            else:
                confidence_votes.append(0.6)

        elif provider == "otx" and result.get("found"):
            pulses = result.get("pulse_count", 0)
            if pulses > 0:
                otx_score = min(15, pulses * 3)
                score += otx_score
                confidence_votes.append(0.75)
                factors.append(f"OTX: {pulses} threat pulses (+{otx_score})")
            else:
                confidence_votes.append(0.5)

    score = min(100, score)
    confidence = sum(confidence_votes) / len(confidence_votes) if confidence_votes else 0.5
    explanation = "; ".join(factors) if factors else "Base score from alert severity"
    return score, round(confidence, 2), explanation


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------

def run_enrichment_pipeline(alert_id: UUID) -> None:
    """Run the full enrichment pipeline for a single alert (BackgroundTask entry point)."""
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        _enrich_alert(db, alert_id)
    except Exception as exc:
        logger.error("Enrichment pipeline failed for alert %s: %s", alert_id, exc, exc_info=True)
    finally:
        db.close()


def _enrich_alert(db: Session, alert_id: UUID) -> None:
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        logger.error("Enrichment: alert %s not found", alert_id)
        return

    if settings.OFFLINE_MODE:
        logger.info("OFFLINE_MODE=true — skipping all external API calls for alert %s", alert_id)
        alert.status = "enriched"
        alert.risk_score = _calculate_risk_score([], alert.normalized_alert or {})[0]
        create_evidence(
            db=db,
            alert_id=alert_id,
            evidence_type="enrichment_completed",
            evidence_data={"offline_mode": True, "providers_queried": [], "iocs_checked": 0},
            source="trustsoc_enrichment",
        )
        db.commit()
        return

    logger.info("Starting enrichment for alert %s | plugins=%d", alert_id, len(registry.all_plugins))
    iocs = alert.normalized_alert.get("iocs", {}) if alert.normalized_alert else {}

    all_enrichment_results: List[Dict] = []
    total_cost = 0.0

    for ioc_type, values in iocs.items():
        for ioc_value in values:
            if not ioc_value:
                continue
            if ioc_type == "ip" and is_private_ip(ioc_value):
                logger.debug("Skipping private IP %s", ioc_value)
                continue
            if total_cost >= settings.ENRICHMENT_BUDGET_PER_ALERT_USD:
                logger.info("Alert %s hit enrichment budget cap ($%.4f)", alert_id, total_cost)
                break

            plugins = registry.get_providers_for(ioc_type)
            result_stored = False

            for plugin in plugins:
                start = time.monotonic()
                result = plugin.enrich(ioc_value, ioc_type)
                elapsed = time.monotonic() - start

                if result is None:
                    continue  # No API key or plugin skipped

                call_cost = plugin.cost_per_call_usd
                total_cost += call_cost

                enrichment_row = models.Enrichment(
                    alert_id=alert_id,
                    enrichment_type=f"{ioc_type}_reputation",
                    provider=plugin.name,
                    query_value=ioc_value,
                    result=result,
                    confidence_score=Decimal("0.0"),
                    cost_usd=Decimal(str(call_cost)),
                    cached=False,
                    api_calls_made=1,
                )
                db.add(enrichment_row)
                db.flush()

                all_enrichment_results.append({
                    "enrichment_type": f"{ioc_type}_reputation",
                    "provider": plugin.name,
                    "ioc": ioc_value,
                    "result": result,
                    "elapsed_ms": round(elapsed * 1000),
                })
                result_stored = True

            if not result_stored:
                # No plugins ran — store mock so evidence isn't empty
                enrichment_row = models.Enrichment(
                    alert_id=alert_id,
                    enrichment_type=f"{ioc_type}_reputation",
                    provider="mock",
                    query_value=ioc_value,
                    result={**_MOCK_RESULT, "ioc": ioc_value, "ioc_type": ioc_type},
                    confidence_score=Decimal("0.0"),
                    cost_usd=Decimal("0.0"),
                    cached=False,
                    api_calls_made=0,
                )
                db.add(enrichment_row)
                db.flush()
                all_enrichment_results.append({
                    "enrichment_type": f"{ioc_type}_reputation",
                    "provider": "mock",
                    "ioc": ioc_value,
                    "result": _MOCK_RESULT,
                })

    risk_score, confidence, explanation = _calculate_risk_score(
        all_enrichment_results, alert.normalized_alert or {}
    )

    alert.risk_score = risk_score
    alert.confidence_score = Decimal(str(confidence))
    alert.status = "enriched"

    create_evidence(
        db=db,
        alert_id=alert_id,
        evidence_type="enrichment_completed",
        evidence_data={
            "providers_queried": [r["provider"] for r in all_enrichment_results],
            "iocs_checked": len(all_enrichment_results),
            "total_cost_usd": round(total_cost, 6),
            "risk_score": risk_score,
            "confidence": confidence,
            "explanation": explanation,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        },
        source="trustsoc_enrichment",
    )

    db.commit()
    logger.info(
        "Enrichment complete | alert=%s | score=%d | confidence=%.2f | cost=$%.4f | plugins=%s",
        alert_id, risk_score, confidence, total_cost,
        [r["provider"] for r in all_enrichment_results],
    )
