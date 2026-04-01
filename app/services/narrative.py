"""
LLM Investigation Narrative Service — Phase 2 differentiator.

Generates plain-English incident summaries from the evidence bundle using the
Claude API. Three sections: What happened | What we know | Recommended actions.

Graceful degradation: returns labeled mock narrative when ANTHROPIC_API_KEY is absent.
Cost tracking: records token_count and cost_usd per generation.
"""

import logging
from decimal import Decimal
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app import models
from app.config import settings

logger = logging.getLogger(__name__)

# Pricing as of claude-sonnet-4-6 (per million tokens)
_INPUT_COST_PER_MILLION = 3.0
_OUTPUT_COST_PER_MILLION = 15.0

_MOCK_NARRATIVE = """**[MOCK — set ANTHROPIC_API_KEY for live narratives]**

**What Happened**
A security alert was received and processed through TrustSOC's automated pipeline. \
The alert was enriched with threat intelligence, correlated against related activity, \
and evaluated by the policy engine. Risk score and confidence have been calculated \
based on available threat intel signals.

**What We Know**
- Alert ingested from source system and normalized
- IOCs extracted and checked against VirusTotal, AbuseIPDB, and OTX
- Risk score reflects severity baseline plus threat intel bonuses
- Correlation engine checked for brute force, lateral movement, and privilege escalation patterns
- Policy engine evaluated all configured YAML rules against this alert

**Recommended Next Steps**
1. Review the evidence trail at `/api/v1/alerts/{alert_id}/evidence`
2. Check for related incidents at `/api/v1/incidents`
3. Submit analyst feedback to close the loop: true_positive, false_positive, or benign
4. Add ANTHROPIC_API_KEY to .env for AI-generated investigation narratives"""


def _build_alert_prompt(alert: models.Alert, enrichments: list, evidence: list) -> str:
    norm = alert.normalized_alert or {}
    iocs = norm.get("iocs", {})

    enrichment_summary = []
    for e in enrichments[:5]:  # cap to avoid token bloat
        r = e.result or {}
        enrichment_summary.append(
            f"  - {e.provider} ({e.enrichment_type}): {r.get('summary', r)}"
        )

    evidence_types = [ev.evidence_type for ev in evidence]

    return f"""You are a senior SOC analyst writing a concise investigation report.

Alert details:
- Title: {norm.get('title', 'Unknown')}
- Severity: {norm.get('severity', 'unknown')}
- Source system: {alert.source_system}
- Source host: {norm.get('source_host', 'unknown')}
- Source IP: {norm.get('source_ip', 'none')}
- User: {norm.get('user', 'none')}
- Risk score: {alert.risk_score}/100
- Confidence: {float(alert.confidence_score or 0):.0%}
- Status: {alert.status}
- IOCs: IPs={iocs.get('ips', [])}, hashes={iocs.get('hashes', [])}, domains={iocs.get('domains', [])}

Threat intel results:
{chr(10).join(enrichment_summary) if enrichment_summary else '  - No enrichment data (API keys may be absent)'}

Evidence trail stages: {', '.join(evidence_types)}

Write a 3-section investigation narrative in plain English for a security analyst:

**What Happened**
(2-4 sentences: timeline, what the alert describes, where it occurred)

**What We Know**
(bullet points: threat intel findings, confidence level, relevant context)

**Recommended Next Steps**
(numbered list: 3-5 concrete actions the analyst should take)

Be specific, factual, and concise. No filler. Do not invent facts not present above."""


def _build_incident_prompt(
    incident: models.Incident,
    alerts: list,
    enrichments: list,
    evidence: list,
) -> str:
    alert_titles = [
        f"  - [{a.source_system}] {(a.normalized_alert or {}).get('title', 'unknown')} (risk={a.risk_score})"
        for a in alerts[:10]
    ]
    enrichment_highlights = []
    for e in enrichments[:8]:
        r = e.result or {}
        enrichment_highlights.append(f"  - {e.provider}: {r.get('summary', str(r)[:120])}")

    mitre = incident.mitre_techniques or []

    return f"""You are a senior SOC analyst writing a concise incident investigation report.

Incident details:
- Title: {incident.title}
- Pattern: {incident.pattern_type}
- Severity: {incident.severity}
- Status: {incident.status}
- MITRE techniques: {', '.join(mitre) if mitre else 'none mapped'}
- Alert count: {len(alerts)}

Related alerts:
{chr(10).join(alert_titles) if alert_titles else '  - none'}

Threat intel highlights:
{chr(10).join(enrichment_highlights) if enrichment_highlights else '  - No enrichment data'}

Write a 3-section investigation narrative in plain English for a security analyst:

**What Happened**
(3-5 sentences: timeline of events, attack pattern detected, assets/users involved)

**What We Know**
(bullet points: confirmed IOCs, threat intel confidence, MITRE mapping context)

**Recommended Next Steps**
(numbered list: 4-6 concrete containment and investigation actions)

Be specific and actionable. No filler. Do not invent facts not present above."""


def generate_alert_narrative(db: Session, alert_id: UUID) -> models.Narrative:
    """Generate or regenerate a narrative for a single alert. Returns the Narrative row."""
    from app.database import SessionLocal

    # Use provided session or open new one (supports both direct calls and background tasks)
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")

    enrichments = (
        db.query(models.Enrichment)
        .filter(models.Enrichment.alert_id == alert_id)
        .all()
    )
    evidence = (
        db.query(models.Evidence)
        .filter(models.Evidence.alert_id == alert_id)
        .order_by(models.Evidence.collected_at)
        .all()
    )

    narrative_text, what_happened, what_we_know, recommended, model_used, tokens, cost, is_mock = (
        _call_llm_for_alert(alert, enrichments, evidence)
    )

    # Upsert: delete existing narrative for this alert before inserting
    db.query(models.Narrative).filter(models.Narrative.alert_id == alert_id).delete()

    narrative = models.Narrative(
        alert_id=alert_id,
        narrative_text=narrative_text,
        what_happened=what_happened,
        what_we_know=what_we_know,
        recommended_actions=recommended,
        model_used=model_used,
        token_count=tokens,
        cost_usd=Decimal(str(cost)),
        is_mock=is_mock,
    )
    db.add(narrative)
    db.commit()
    db.refresh(narrative)
    logger.info("Narrative generated alert_id=%s mock=%s tokens=%d", alert_id, is_mock, tokens)
    return narrative


def generate_incident_narrative(db: Session, incident_id: UUID) -> models.Narrative:
    """Generate or regenerate a narrative for an incident."""
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    alerts = (
        db.query(models.Alert)
        .filter(models.Alert.incident_id == incident_id)
        .all()
    )
    alert_ids = [a.id for a in alerts]
    enrichments = (
        db.query(models.Enrichment)
        .filter(models.Enrichment.alert_id.in_(alert_ids))
        .all()
    ) if alert_ids else []
    evidence = (
        db.query(models.Evidence)
        .filter(models.Evidence.incident_id == incident_id)
        .order_by(models.Evidence.collected_at)
        .all()
    )

    narrative_text, what_happened, what_we_know, recommended, model_used, tokens, cost, is_mock = (
        _call_llm_for_incident(incident, alerts, enrichments, evidence)
    )

    db.query(models.Narrative).filter(models.Narrative.incident_id == incident_id).delete()

    narrative = models.Narrative(
        incident_id=incident_id,
        narrative_text=narrative_text,
        what_happened=what_happened,
        what_we_know=what_we_know,
        recommended_actions=recommended,
        model_used=model_used,
        token_count=tokens,
        cost_usd=Decimal(str(cost)),
        is_mock=is_mock,
    )
    db.add(narrative)
    db.commit()
    db.refresh(narrative)
    logger.info("Narrative generated incident_id=%s mock=%s tokens=%d", incident_id, is_mock, tokens)
    return narrative


# ---------------------------------------------------------------------------
# Internal LLM calls
# ---------------------------------------------------------------------------

def _call_llm_for_alert(alert, enrichments, evidence):
    if not settings.ANTHROPIC_API_KEY:
        mock = _MOCK_NARRATIVE.replace("{alert_id}", str(alert.id))
        return mock, None, None, None, "mock", 0, 0.0, True

    prompt = _build_alert_prompt(alert, enrichments, evidence)
    return _call_anthropic(prompt)


def _call_llm_for_incident(incident, alerts, enrichments, evidence):
    if not settings.ANTHROPIC_API_KEY:
        mock = _MOCK_NARRATIVE.replace("{alert_id}", str(incident.id))
        return mock, None, None, None, "mock", 0, 0.0, True

    prompt = _build_incident_prompt(incident, alerts, enrichments, evidence)
    return _call_anthropic(prompt)


def _call_anthropic(prompt: str):
    """Call Claude API, parse 3-section response, return 8-tuple."""
    import anthropic

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
    model = "claude-sonnet-4-6"

    try:
        message = client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        full_text = message.content[0].text
        input_tokens = message.usage.input_tokens
        output_tokens = message.usage.output_tokens
        total_tokens = input_tokens + output_tokens
        cost = (
            input_tokens / 1_000_000 * _INPUT_COST_PER_MILLION
            + output_tokens / 1_000_000 * _OUTPUT_COST_PER_MILLION
        )

        what_happened = _extract_section(full_text, "What Happened")
        what_we_know = _extract_section(full_text, "What We Know")
        recommended = _extract_section(full_text, "Recommended Next Steps")

        return full_text, what_happened, what_we_know, recommended, model, total_tokens, cost, False

    except Exception as exc:
        logger.error("Anthropic API error: %s", exc)
        mock = _MOCK_NARRATIVE + f"\n\n[API error: {exc}]"
        return mock, None, None, None, "mock_error", 0, 0.0, True


def _extract_section(text: str, section_title: str) -> Optional[str]:
    """Pull a **Section Title** block out of the narrative text."""
    import re
    pattern = rf"\*\*{re.escape(section_title)}\*\*\s*(.*?)(?=\*\*|$)"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else None
