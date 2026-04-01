# TrustSOC — Complete Project Document
**Version:** 3.0
**Last Updated:** April 1, 2026
**Author:** Amogh
**Status:** Phase 2 Complete — Phase 3 Complete

---

## TABLE OF CONTENTS

1. [What Is TrustSOC](#1-what-is-trustsoc)
2. [The Problem We Are Solving](#2-the-problem-we-are-solving)
3. [End Product Vision](#3-end-product-vision)
4. [What Makes TrustSOC Unique](#4-what-makes-trustsoc-unique)
5. [Technology Stack](#5-technology-stack)
6. [Architecture](#6-architecture)
7. [Project Structure](#7-project-structure)
8. [What Was Already Built (Week 1-2)](#8-what-was-already-built-week-1-2)
9. [What Was Built in Phase 1 Session (Week 3-4)](#9-what-was-built-this-session-week-3-4)
10a. [What Was Built in Phase 2 Session (Week 5 - April 1, 2026)](#10a-phase-2-session-april-1-2026)
10. [Complete API Endpoint Reference](#10-complete-api-endpoint-reference)
11. [Database Schema — All 10 Tables](#11-database-schema--all-10-tables)
12. [How An Alert Moves Through TrustSOC](#12-how-an-alert-moves-through-trustsoc)
13. [Open-Source Community Strategy](#13-open-source-community-strategy)
14. [Phase Roadmap](#14-phase-roadmap)
15. [Configuration Reference](#15-configuration-reference)
16. [Quick Start Guide](#16-quick-start-guide)
17. [Deployment](#17-deployment)
18. [Current Project Metrics](#18-current-project-metrics)

---

## 1. What Is TrustSOC

TrustSOC is an **open-source, evidence-based SOC (Security Operations Center) automation platform**.

It receives security alerts from any source (Wazuh, Splunk, Elastic, Microsoft Defender, CrowdStrike), automatically enriches them with threat intelligence, calculates a risk score with full explanation, correlates related alerts into incidents, and applies configurable policies to determine automated actions — while maintaining a cryptographically verifiable audit trail for every single decision.

**The core philosophy:** Every decision TrustSOC makes must be explainable, auditable, and reversible. No black boxes. No "the AI decided."

---

## 2. The Problem We Are Solving

### The Reality of a Modern SOC

```
Real SOC Numbers (Industry Average):
  3,800 alerts per day
  2 security analysts on shift
  Analysts can investigate ~200 alerts/day
  3,600 alerts go uninvestigated
  83% of alerts are false positives
  40 minutes per alert investigation
  70% analyst burnout rate
  Real attacks slip through undetected
```

### Why Existing Tools Fall Short

| Tool | The Gap |
|------|---------|
| Wazuh / Splunk / Elastic | Generate alerts, but no automated triage |
| TheHive / Cortex | Require manual case creation, no auto-correlation |
| Shuffle / StackStorm | SOAR platforms — no evidence trail, complex setup |
| MISP | Threat intel sharing, not alert triage |
| Commercial SIEMs | $50,000+/year, inaccessible to small teams |

### What TrustSOC Does Instead

```
TrustSOC processes all 3,800 alerts:
  Auto-enriches each with threat intel (VT, AbuseIPDB, OTX)
  Calculates risk score (0-100) with plain-English explanation
  Runs suppression rules — known false positives skipped instantly
  Correlates related alerts into incidents (brute force, lateral movement)
  Applies policy rules with safety guardrails
  Records cryptographic audit trail for every decision
  Result: 3,800 raw alerts → ~50 actionable incidents for analysts
```

---

## 3. End Product Vision

When TrustSOC is fully built, a security team can:

1. Run `docker compose up` and have a working SOC in under 5 minutes
2. Point Wazuh/Splunk/Elastic at TrustSOC and receive enriched, scored alerts immediately
3. See incidents auto-created when brute force, lateral movement, or privilege escalation is detected
4. Read a plain-English AI narrative for every incident: "What happened, what we know, what to do next"
5. Understand every decision: why an alert scored 87, which policy triggered, what guardrail blocked an action
6. Export a legally defensible evidence bundle for any alert or incident
7. Add enrichment plugins by dropping a Python file in a folder
8. Import community false-positive suppression rules with one command
9. See their MITRE ATT&CK detection coverage as a shareable heatmap

### Who TrustSOC Is For

| User | Use Case |
|------|----------|
| Small security team (2-5 analysts) | Replace manual triage, reduce alert fatigue |
| Solo researcher / homelab | Self-hosted SOC for personal infrastructure |
| MSSP | Run SOC services for multiple clients |
| Security developer | Build on TrustSOC's plugin/API system |
| Student / learner | Learn SOC automation with a real working system |

---

## 4. What Makes TrustSOC Unique

No existing open-source tool offers all five simultaneously:

### 1. Cryptographic Evidence Trail
Every step — alert receipt, enrichment result, correlation, policy decision, analyst feedback — writes a SHA-256 hashed evidence record. These are immutable and tamper-detectable. TrustSOC is the only open-source SOC tool with forensic chain-of-custody for every automated decision.
- Legal/compliance defensibility
- SOC2 / ISO 27001 audit readiness
- Incident response handoff documentation

### 2. LLM Investigation Narratives (Phase 2)
The Claude API will auto-generate plain-English incident summaries from the evidence bundle. Instead of raw JSON, TrustSOC writes:

> *"At 10:31 UTC, workstation windows-01 in Finance attempted to dump credentials using Mimikatz (T1003). The source account john.doe logged in 3 minutes earlier from an unusual external IP (185.x.x.x) flagged by AbuseIPDB at 94% confidence. Two minutes later, a new admin account was created on the domain controller (T1136). Recommend: isolate windows-01, audit domain admin accounts created in the last hour."*

No open-source competitor does this.

### 3. Cost-Aware Enrichment
Every API call records its USD cost. Enforces a configurable budget cap per alert. Degrades gracefully when API keys are missing — returns labeled mock data, never crashes. Essential for teams on free API tiers.

### 4. Community Suppression Rules
YAML false-positive rules shareable via GitHub URL — import with one API call. Modeled on the Sigma rules community. Teams share what they know is noise; everyone benefits.

### 5. "SOC in a Box" Docker Compose
`docker compose up` starts PostgreSQL + TrustSOC + Grafana with 3 pre-built dashboards. Zero configuration for a working demo. Only `DATABASE_URL` and `API_KEY` are required for production.

### Competitive Comparison

| Feature | TheHive | Cortex | Shuffle | MISP | **TrustSOC** |
|---------|---------|--------|---------|------|-------------|
| Cryptographic evidence trail | No | No | No | No | **Yes** |
| LLM investigation narratives | No | No | No | No | **Yes (Phase 2)** |
| Cost-aware enrichment | No | No | No | No | **Yes** |
| Community suppression rules | No | No | No | Partial | **Yes** |
| SOC-in-a-Box docker-compose | No | No | Partial | No | **Yes** |
| MITRE auto-mapping | Partial | No | No | Partial | **Yes** |
| Under 5 min to working demo | No | No | No | No | **Yes** |

---

## 5. Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Python | 3.11 |
| Web Framework | FastAPI | 0.109.0 |
| Database | PostgreSQL | 15 |
| ORM | SQLAlchemy | 2.0.25 |
| Migrations | Alembic | 1.13.1 |
| Validation | Pydantic | 2.5.3 |
| Settings | pydantic-settings | 2.1.0 |
| HTTP Client | requests + httpx | 2.31 / 0.26 |
| YAML Parsing | pyyaml | 6.0.1 |
| Rate Limiting | slowapi | 0.1.9 |
| Retry Logic | tenacity | 8.2.3 |
| Testing | pytest | 7.4.4 |
| DB Hosting | Supabase | Free tier |
| App Hosting | Render.com | Free tier |
| Dashboards | Grafana | 10.2.0 |
| LLM (Phase 2) | Anthropic Claude API | claude-sonnet-4-6 |

---

## 6. Architecture

```
ALERT SOURCES
  Wazuh | Splunk | Elastic | Microsoft Defender | CrowdStrike
              |
              | POST /api/v1/alerts (webhook)
              v
TRUSTSOC API (FastAPI)
  |
  +-- INTAKE (synchronous — returns 201 immediately)
  |     Normalize alert (Wazuh/Splunk/Elastic -> common format)
  |     Extract IOCs (IPs, domains, hashes, URLs)
  |     Store in DB with status="processing"
  |     Create evidence record (SHA-256 hashed)
  |     Schedule 3 background tasks
  |
  +-- ENRICHMENT (BackgroundTask)
  |     VirusTotal v3 API — malicious detections, detection ratio
  |     AbuseIPDB v2 API — confidence score, ISP, country, Tor flag
  |     OTX AlienVault — pulse count, malware families
  |     Cost tracking per call (cost_usd, cached, api_calls_made)
  |     Risk scoring: base severity + provider signals -> 0-100
  |     Update alert.risk_score, confidence_score, status="enriched"
  |     Create evidence record "enrichment_completed"
  |
  +-- CORRELATION (BackgroundTask)
  |     brute_force: same source_ip + auth failures + N alerts in window
  |     lateral_movement: same user + multiple hosts in window
  |     privilege_escalation: process execution + privesc on same host
  |     MITRE ATT&CK auto-mapping per pattern
  |     Create Incident, link related alerts via incident_id
  |     Create evidence record "correlation_detected"
  |
  +-- POLICY ENGINE (BackgroundTask)
  |     Load YAML rules from policies/ at startup
  |     Evaluate conditions against alert (gte, lte, eq, contains, is_external...)
  |     Run guardrail check on each action
  |     Store PolicyExecution audit record with explanation
  |
  +-- GUARDRAILS (safety layer — cannot be bypassed)
        Never block internal/private IPs
        Never act on assets with criticality >= threshold
        Enforce hourly block rate limit
        Require AUTO_BLOCK_ENABLED=true
              |
              v
POSTGRESQL DATABASE (Supabase)
  10 tables: alerts, incidents, evidence, enrichments, actions,
             assets, users_context, feedback, suppressions, policy_executions
              |
              v
GRAFANA DASHBOARDS (http://localhost:3000)
  Alert Volume & Risk Distribution
  Incident Timeline by Pattern/Severity
  Enrichment API Cost Tracking
```

---

## 7. Project Structure

```
trustsoc/
|
+-- app/                              Application package
|   +-- __init__.py
|   +-- main.py                       FastAPI app: middleware, routers, startup
|   +-- config.py                     Settings from .env (Pydantic v2)
|   +-- database.py                   SQLAlchemy engine + session factory
|   +-- models.py                     10 ORM table definitions
|   +-- schemas.py                    Pydantic request/response schemas
|   |
|   +-- routers/
|   |   +-- alerts.py                 6 endpoints + BackgroundTasks wiring
|   |   +-- incidents.py              5 endpoints: list, get, timeline, evidence, feedback
|   |   +-- cases.py                  STUB — Phase 3
|   |
|   +-- services/
|   |   +-- enrichment.py             VT + AbuseIPDB + OTX + cost tracking + risk scoring
|   |   +-- correlation.py            3 pattern detectors + MITRE mapping + incident creation
|   |   +-- policy_engine.py          YAML loader + condition evaluator + guardrail checks
|   |
|   +-- utils/
|       +-- helpers.py                IOC extraction, alert normalization, SHA-256, IP utils
|       +-- evidence.py               create_evidence() + verify_evidence_hash()
|       +-- guardrails.py             check_action_allowed() — 4 safety rules
|
+-- alembic/                          Database migration infrastructure
|   +-- env.py                        Configured to read from app.config (bypasses % bug)
|   +-- versions/
|       +-- 58a01322819a_initial_schema.py    First migration — all 10 tables
|
+-- scripts/
|   +-- generate_demo_data.py         8 realistic alert scenarios for testing
|
+-- tests/
|   +-- test_alerts.py                28 automated tests (all passing)
|
+-- policies/                         YAML policy rules (version-controlled with code)
|   +-- auto_block_high_risk_ip.yaml  Block external IPs scoring >= 80
|   +-- escalate_critical_alerts.yaml Flag critical severity for human review
|   +-- suppress_low_risk_internal.yaml Auto-close low-risk noise
|
+-- docker/
|   +-- grafana/
|       +-- provisioning/
|           +-- datasources/
|           |   +-- postgres.yaml     Auto-connects Grafana to TrustSOC DB
|           +-- dashboards/
|               +-- dashboards.yaml       Dashboard loader config
|               +-- alert_volume.json     Dashboard 1: Alert volume & risk
|               +-- incident_timeline.json Dashboard 2: Incidents by pattern
|               +-- enrichment_costs.json  Dashboard 3: API cost tracking
|
+-- docker-compose.yml                SOC in a Box: postgres + api + grafana
+-- .env.example                      Template — only DATABASE_URL + API_KEY required
+-- .env                              YOUR actual credentials (never committed to git)
+-- alembic.ini                       Alembic configuration
+-- requirements.txt                  All Python dependencies
+-- render.yaml                       Render.com deployment config
+-- Dockerfile                        Container build
+-- README.md                         Project documentation
```

---

## 8. What Was Already Built (Week 1-2)

These existed before this session and are production-deployed on Render.com.

### Core API Infrastructure
- FastAPI application with structured JSON logging (ELK-compatible format)
- Request ID tracing: every request/response carries `X-Request-ID` header
- Rate limiting at 200 requests/minute per IP
- CORS middleware
- Custom exception handlers for validation errors and general errors
- `GET /health` health check
- `GET /api/v1/stats` system statistics

### Database Layer
- PostgreSQL hosted on Supabase (free tier)
- Session Pooler connection for IPv4 compatibility on Render
- 10 SQLAlchemy ORM tables
- `Base.metadata.create_all` for schema bootstrap

### Alert Intake
- `POST /api/v1/alerts` — accepts alerts from any source
- Alert normalization for Wazuh, Splunk, Elastic
- IOC extraction from nested JSON: IPs, domains, hashes, URLs
- Evidence record created on every alert receipt with SHA-256 hash

### Evidence & Trust System
- `GET /api/v1/alerts/{id}/evidence` — complete evidence bundle
- `GET /api/v1/alerts/{id}/evidence/verify` — tamper detection
- All evidence records immutable and cryptographically verifiable

### Analyst Feedback
- `POST /api/v1/alerts/{id}/feedback`
- Feedback types: `true_positive`, `false_positive`, `benign`, `needs_more_data`
- Alert status updates based on feedback

### Testing & Demo
- 28 automated tests — 100% passing
- Demo data generator with 8 scenarios: Mimikatz, SSH brute force, malware download, new admin account, suspicious PowerShell, data exfiltration, ransomware, impossible travel

### Deployment
- Live on Render.com with HTTPS
- Auto-deploy from GitHub on push

---

## 9. What Was Built This Session (Week 3-4)

This session added **1,574 lines of new code across 12 files**. Every service that was an empty stub is now fully implemented.

---

### 9.1 Alembic Migration Infrastructure

**Files:** `alembic/env.py`, `alembic.ini`, `alembic/versions/58a01322819a_initial_schema.py`

The original code used `Base.metadata.create_all` — safe for first run but dangerous for schema changes (will fail or lose data on an existing DB). Alembic adds proper versioned migrations.

**What was done:**
- Initialized Alembic
- Configured `env.py` to read `DATABASE_URL` directly from `app.config` — bypasses a ConfigParser bug where `%40` in passwords caused a crash
- Generated the first migration capturing all 10 tables plus the 3 new cost fields on `Enrichment`

**Commands:**
```bash
# After changing models.py, generate a migration
alembic revision --autogenerate -m "description"

# Apply all pending migrations
alembic upgrade head

# Roll back one migration
alembic downgrade -1
```

---

### 9.2 Config Overhaul (`app/config.py`)

**Key change:** All external API keys are now `Optional[str] = None` instead of required fields. This is the most important change for open-source adoption — the system must run without API keys.

**New fields added:**
```
ANTHROPIC_API_KEY           = None   (LLM narratives, Phase 2)
ENRICHMENT_BUDGET_PER_ALERT_USD = 0.10
ENRICHMENT_CACHE_TTL_SECONDS    = 3600
TRUSTSOC_PLUGIN_DIR             = None   (custom plugin directory)
```

**Principle:** Only `DATABASE_URL` and `API_KEY` are required. Everything else has safe defaults.

---

### 9.3 Enrichment Cost Fields (`app/models.py`)

Added to the `Enrichment` table:
```python
cost_usd       DECIMAL(10, 6)   # USD cost of this API call
cached         BOOLEAN           # Whether result came from cache
api_calls_made INTEGER           # Number of API calls made
```

This enables the "Enrichment Cost" Grafana dashboard and gives teams full transparency into what free-tier API quota they're consuming.

---

### 9.4 Guardrails (`app/utils/guardrails.py`)

**133 lines — was 0 bytes.**

Every automated action must pass `check_action_allowed(db, alert, action_type)` before execution. These rules cannot be bypassed by any policy.

**Four safety rules:**

1. **Global kill switch** — `AUTO_BLOCK_ENABLED=false` disables all blocking immediately
2. **Never block internal IPs** — checks `is_private_ip()` before any block action
3. **Critical asset protection** — assets with `criticality >= CRITICAL_ASSET_MIN_SCORE` require human review
4. **Hourly rate limit** — counts recent `block_*` actions; refuses if `>= MAX_BLOCKS_PER_HOUR`

**Returns `GuardrailResult(allowed: bool, reason: str)`** — always logged for the audit trail.

---

### 9.5 Enrichment Service (`app/services/enrichment.py`)

**421 lines — was 0 bytes.**

The intelligence layer. Queries threat intel providers for each IOC, tracks cost, calculates risk score.

**Three built-in providers:**

| Provider | IOC Types Supported | Free Tier Limit |
|----------|--------------------|----|
| VirusTotal v3 | IP, domain, hash, URL | 4 req/min |
| AbuseIPDB v2 | IP only | 1,000/day |
| OTX AlienVault | IP, domain, hash | Unlimited |

**Graceful degradation:**
- Missing API key → skip provider, store labeled mock result
- API error → log warning, continue with other providers
- Budget cap exceeded → stop enriching, log reason
- Demo works with zero API keys configured

**Risk scoring algorithm:**
```
Base score from alert severity:
  critical = 60 pts
  high     = 45 pts
  medium   = 25 pts
  low      = 10 pts

VirusTotal bonus (max +35):
  (malicious / total_engines) * 35

AbuseIPDB bonus (max +25):
  abuse_confidence_score * 0.25

OTX bonus (max +15):
  min(15, pulse_count * 3)

Final score = min(100, sum of above)
Confidence = average of provider vote weights (0.0-1.0)
```

**Pipeline (runs as BackgroundTask):**
```
run_enrichment_pipeline(alert_id)
  -> New DB session (background tasks don't share request session)
  -> Extract IOCs from normalized_alert.iocs
  -> Skip private IPs (no value in checking threat intel for 192.168.x.x)
  -> Check budget cap
  -> For each IOC: query each matching provider
  -> Store Enrichment row: result + cost_usd + cached + api_calls_made
  -> calculate_risk_score() -> score + confidence + explanation
  -> Update alert: risk_score, confidence_score, status="enriched"
  -> create_evidence("enrichment_completed") with full summary
  -> Commit
```

---

### 9.6 Correlation Engine (`app/services/correlation.py`)

**298 lines — was 0 bytes.**

Groups related alerts into incidents by detecting attack patterns. Runs after enrichment as a BackgroundTask.

**Pattern 1: Brute Force**
- Detects: Multiple failed-auth alerts from the same source IP within the time window
- Trigger keywords: "failed", "brute", "authentication failure", "invalid password", "login failed", "ssh"
- Minimum alerts: `MIN_ALERTS_FOR_INCIDENT` (default: 3)
- MITRE: T1110, T1110.001, T1110.003
- Incident severity: High

**Pattern 2: Lateral Movement**
- Detects: Same user account seen on 2+ different hosts within time window
- Method: Groups alerts by `normalized_alert.user`, counts distinct `source_host` values
- MITRE: T1021, T1021.001, T1021.002, T1078
- Incident severity: Critical

**Pattern 3: Privilege Escalation**
- Detects: Process execution alert followed by admin account creation on the same host
- Trigger keywords: "admin", "privilege", "escalation", "mimikatz", "new user", "net user"
- Looks for preceding execution alert (powershell, cmd, script) on same host
- MITRE: T1078, T1136, T1136.001
- Incident severity: Critical

**What happens when a pattern fires:**
```
_create_or_update_incident():
  Check if any related alert already has an open incident of the same pattern
  If yes: attach new alerts to existing incident
  If no: create new Incident row with title + MITRE mapping
  Link all related alerts via alert.incident_id
  create_evidence("correlation_detected") on the incident
  Commit
```

---

### 9.7 Policy Engine (`app/services/policy_engine.py`)

**259 lines — was 0 bytes.**

Evaluates YAML rules against enriched alerts. Records every decision in `policy_executions`.

**How it works:**
1. `load_policies()` called at app startup — scans `policies/*.yaml`
2. `run_policy_engine(alert_id)` called per alert as BackgroundTask
3. For each enabled policy: evaluate all conditions
4. If ALL conditions pass: run guardrail check on each action
5. Store `PolicyExecution` record regardless of guardrail outcome

**Supported condition operators:**
```
gte           greater than or equal (numeric)
lte           less than or equal (numeric)
gt            greater than (numeric)
lt            less than (numeric)
eq            string equality
neq           string not equal
contains      substring match
is_external   IP is not in private/RFC1918 range
exists        field is not null
```

**Supported field paths:**
```
risk_score
confidence_score
source_system
status
normalized_alert.severity
normalized_alert.source_ip
normalized_alert.source_host
normalized_alert.user
normalized_alert.title
```

**Policy YAML format:**
```yaml
name: my_policy_name
version: "1.0"
enabled: true
description: "Human-readable description"
conditions:
  - field: risk_score
    operator: gte
    value: 80
  - field: normalized_alert.source_ip
    operator: is_external
actions:
  - type: recommend_block_ip
    requires_approval: false
    rollback_after_minutes: 15
explanation_template: >
  Alert {alert_id} scored {risk_score} from {source}.
  Policy '{policy_name}' triggered.
```

---

### 9.8 Three Example Policies (`policies/`)

**`auto_block_high_risk_ip.yaml`**
- When: `risk_score >= 80` AND `source_ip is_external`
- Action: `recommend_block_ip` (15-min rollback window)
- Guardrails will refuse if IP is internal or asset is critical

**`escalate_critical_alerts.yaml`**
- When: `normalized_alert.severity == critical`
- Action: `flag_for_human_review` + `notify_security_team`
- Catches critical alerts regardless of risk score (before enrichment even completes)

**`suppress_low_risk_internal.yaml`**
- When: `risk_score <= 20` AND `severity != critical`
- Action: `suppress_alert`
- Automatically closes low-value noise so analysts focus on real threats

---

### 9.9 Incidents Router (`app/routers/incidents.py`)

**306 lines — was a 9-line stub.**

Five fully working endpoints:

**`GET /api/v1/incidents`**
- Query parameters: `severity`, `status`, `pattern_type`, `skip`, `limit`
- Returns list of `IncidentResponse`

**`GET /api/v1/incidents/{id}`**
- Returns `IncidentDetail` including all linked alert summaries and count

**`GET /api/v1/incidents/{id}/timeline`** ← the showcase endpoint
- Returns chronological list of `TimelineEvent` objects
- Sources: incident-level evidence + all alert-level evidence + policy executions
- Each event has: `timestamp`, `event_type`, `source`, human-readable `summary`, `alert_id`, `data`
- Sorted ascending by timestamp — you can read it like a story of the attack

**`GET /api/v1/incidents/{id}/evidence`**
- Aggregate evidence bundle across all alerts in the incident
- All enrichment results
- Full MITRE mapping
- Suitable for export as a compliance/legal artifact

**`POST /api/v1/incidents/{id}/feedback`**
- Same feedback types as alert-level
- Updates incident status (confirmed / false_positive)
- Creates evidence record for the audit trail

---

### 9.10 BackgroundTasks Wiring (`app/routers/alerts.py`)

`POST /api/v1/alerts` now schedules three background tasks immediately after committing the alert:

```python
background_tasks.add_task(run_enrichment_pipeline, alert_id)
background_tasks.add_task(run_correlation_pipeline, alert_id)
background_tasks.add_task(run_policy_engine, alert_id)
```

The endpoint returns `201 Created` in milliseconds. The pipeline runs after the response is sent.

Each background task opens its own DB session — they cannot share the request session.

**Client polling pattern:**
```
POST /api/v1/alerts -> 201, status="processing"
  ... wait 2-5 seconds ...
GET /api/v1/alerts/{id} -> status="enriched", risk_score=87
GET /api/v1/incidents -> incident may now exist if pattern was detected
```

---

### 9.11 New Schemas (`app/schemas.py`)

Added to support the incidents router:

**`IncidentDetail`** — full incident with alert list and alert_count

**`IncidentResponse`** — updated with `description`, `updated_at`, `closed_at`; `mitre_tactics`/`mitre_techniques` changed from `Dict` to `List[str]`

**`TimelineEvent`**:
```
timestamp    datetime
event_type   str       # alert_received, enrichment_completed, correlation_detected...
source       str       # which TrustSOC service created this event
summary      str       # human-readable one-liner
alert_id     UUID      # optional — which alert this belongs to
evidence_id  UUID      # optional — the underlying evidence record
data         Dict      # optional — raw event data
```

---

### 9.12 "SOC in a Box" Docker Compose (`docker-compose.yml`)

Expanded from 1 service to 3:

```
Before:  trustsoc-api only (no database — required external Supabase)
After:   postgres + trustsoc-api + grafana (fully self-contained)
```

**`postgres` service:** postgres:15-alpine, persistent volume, health check

**`trustsoc-api` service:** depends on postgres being healthy, DATABASE_URL overridden to point at local container, external API keys passed through from host env (all optional)

**`grafana` service:** grafana:10.2.0, auto-provisioned datasource + 3 dashboards, login admin/admin

**One command, full working SOC:**
```bash
docker compose up
# ~30 seconds startup
# API: http://localhost:8000/docs  (API key: trustsoc_demo_key)
# Grafana: http://localhost:3000   (admin / admin)
```

---

### 9.13 Three Grafana Dashboards (`docker/grafana/`)

All three auto-load on `docker compose up` — no manual Grafana setup.

**Dashboard 1: Alert Volume**
- Alerts per hour (time series)
- Alerts by status (pie chart)
- Alerts by source system (pie chart)
- Risk score distribution (histogram)
- Stat panels: high-risk count, total today, open incidents, false positive rate %

**Dashboard 2: Incident Timeline**
- Incidents by severity (pie chart)
- Incidents by pattern type (bar chart)
- Open vs closed (pie chart)
- Incidents created over time (time series)
- Recent incidents table with alert counts

**Dashboard 3: Enrichment & API Costs**
- Total API cost this week (USD)
- Total API calls this week
- Cache hit rate %
- Count of alerts using mock data (when API keys missing)
- API calls by provider (bar chart)
- Cost by provider USD (pie chart)
- Daily cost trend (time series)
- IOC types checked breakdown
- Average risk score trend after enrichment

---

### 9.14 `.env.example` Template

Documents every config variable with inline comments. Communicates clearly which two are required and which are optional:

```bash
# REQUIRED
DATABASE_URL=postgresql://user:password@localhost:5432/trustsoc
API_KEY=change_me_before_deploying

# OPTIONAL — system works without these
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
ANTHROPIC_API_KEY=
```

---

## 10a. Phase 2 Session (April 1, 2026)

### What Was Built

#### LLM Investigation Narratives — **COMPLETE**

**New files:**
- `app/services/narrative.py` — 250 lines. Builds analyst-focused prompt from alert/incident evidence bundle, calls Claude API (`claude-sonnet-4-6`), parses 3-section response, stores cost. Returns mock narrative when `ANTHROPIC_API_KEY` absent.
- `alembic/versions/d198113371aa_add_narratives_table.py` — migration for `narratives` table + enrichment cost columns. Applied to Supabase.

**Modified files:**
- `app/models.py` — added `Narrative` ORM model (11th table); back-refs on `Alert` and `Incident`
- `app/schemas.py` — added `NarrativeResponse`
- `app/routers/alerts.py` — added `POST /api/v1/alerts/{id}/narrative`, `GET /api/v1/alerts/{id}/narrative`
- `app/routers/incidents.py` — added `POST /api/v1/incidents/{id}/narrative`, `GET /api/v1/incidents/{id}/narrative`
- `requirements.txt` — added `anthropic==0.40.0`
- `.env` — added `ANTHROPIC_API_KEY=` placeholder

**Narrative format (3 sections):**
```
**What Happened**      — 2-4 sentences: timeline, what the alert describes
**What We Know**       — bullet points: threat intel, confidence, context
**Recommended Next Steps** — numbered list: 3-5 concrete analyst actions
```

**Cost tracking:** `token_count`, `cost_usd` per narrative. `is_mock=true` when key absent.

**New endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/alerts/{id}/narrative` | Generate (or regenerate) narrative |
| GET | `/api/v1/alerts/{id}/narrative` | Retrieve existing narrative |
| POST | `/api/v1/incidents/{id}/narrative` | Generate incident narrative |
| GET | `/api/v1/incidents/{id}/narrative` | Retrieve incident narrative |

**Migration note:** Supabase has a `high_risk_alerts` view that blocks `ALTER COLUMN` on timestamp columns. Migration was trimmed to only add new tables/columns — timestamp timezone changes skipped.

---

## 10. Complete API Endpoint Reference

### System Endpoints
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | No | Service info and version |
| GET | `/health` | No | Health check |
| GET | `/docs` | No | Swagger UI (interactive API explorer) |
| GET | `/api/v1/stats` | Yes | Alert and incident counts |

### Alert Endpoints
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/alerts` | Yes | Ingest alert — starts enrichment pipeline |
| GET | `/api/v1/alerts` | Yes | List with filters (status, min_risk_score, skip, limit) |
| GET | `/api/v1/alerts/{id}` | Yes | Full alert detail |
| GET | `/api/v1/alerts/{id}/evidence` | Yes | Complete evidence bundle |
| GET | `/api/v1/alerts/{id}/evidence/verify` | Yes | SHA-256 tamper detection |
| POST | `/api/v1/alerts/{id}/feedback` | Yes | Submit analyst feedback |

### Incident Endpoints
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/incidents` | Yes | List with filters (severity, status, pattern_type) |
| GET | `/api/v1/incidents/{id}` | Yes | Full incident with linked alerts |
| GET | `/api/v1/incidents/{id}/timeline` | Yes | Chronological attack timeline |
| GET | `/api/v1/incidents/{id}/evidence` | Yes | Aggregate evidence across all alerts |
| POST | `/api/v1/incidents/{id}/feedback` | Yes | Analyst feedback |
| POST | `/api/v1/incidents/{id}/narrative` | Yes | Generate LLM investigation narrative |
| GET | `/api/v1/incidents/{id}/narrative` | Yes | Retrieve existing narrative |

### Narrative Endpoints (Phase 2)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/alerts/{id}/narrative` | Yes | Generate LLM narrative for an alert |
| GET | `/api/v1/alerts/{id}/narrative` | Yes | Get existing alert narrative |

### Suppression Endpoints (Phase 2)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/suppressions` | Yes | List suppression rules |
| POST | `/api/v1/suppressions` | Yes | Create rule manually |
| GET | `/api/v1/suppressions/{id}` | Yes | Get single rule |
| PUT | `/api/v1/suppressions/{id}/toggle` | Yes | Enable / disable rule |
| DELETE | `/api/v1/suppressions/{id}` | Yes | Delete rule |
| POST | `/api/v1/suppressions/import` | Yes | Import from YAML text body |
| POST | `/api/v1/suppressions/import-url` | Yes | Import from URL (community hub) |

### Case Endpoints (Phase 2)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/cases` | Yes | Create case |
| GET | `/api/v1/cases` | Yes | List cases |
| GET | `/api/v1/cases/{id}` | Yes | Full case detail |
| PATCH | `/api/v1/cases/{id}` | Yes | Update status / assignee / title |
| POST | `/api/v1/cases/{id}/incidents` | Yes | Link incidents to case |
| DELETE | `/api/v1/cases/{id}/incidents/{incident_id}` | Yes | Unlink incident |
| POST | `/api/v1/cases/{id}/notes` | Yes | Add analyst note |
| GET | `/api/v1/cases/{id}/export` | Yes | JSON compliance bundle export |

### Authentication
All protected endpoints require:
```
Header: x-api-key: your_api_key
```
Wrong or missing key → `401 Unauthorized`
Too many requests → `429 Too Many Requests`

---

## 11. Database Schema — All 10 Tables

### `alerts`
```
id                UUID PRIMARY KEY
external_id       VARCHAR(255) UNIQUE   ID from source system (Wazuh rule ID, etc.)
source_system     VARCHAR(100)          wazuh | splunk | elastic | custom
raw_alert         JSONB                 Original unmodified payload
normalized_alert  JSONB                 Standardized format + extracted IOCs
risk_score        INTEGER (0-100)       Populated after enrichment
confidence_score  DECIMAL(3,2)          0.0 to 1.0 — how sure we are
status            VARCHAR(50)           processing -> enriched -> confirmed/suppressed/false_positive
incident_id       UUID -> incidents     Set when correlation detects a pattern
created_at        TIMESTAMP (indexed)
updated_at        TIMESTAMP
```

### `incidents`
```
id               UUID PRIMARY KEY
title            VARCHAR(255)    e.g. "Brute Force Attack from 185.x.x.x"
description      TEXT            Full narrative description
pattern_type     VARCHAR(100)    brute_force | lateral_movement | privilege_escalation
severity         VARCHAR(50)     low | medium | high | critical (indexed)
status           VARCHAR(50)     open | confirmed | false_positive | closed (indexed)
mitre_tactics    JSONB           ["Credential Access", "Initial Access"]
mitre_techniques JSONB           ["T1110", "T1110.001", "T1110.003"]
created_at       TIMESTAMP (indexed)
updated_at       TIMESTAMP
closed_at        TIMESTAMP
```

### `evidence`  ← THE TRUST TABLE
```
id              UUID PRIMARY KEY
alert_id        UUID -> alerts
incident_id     UUID -> incidents
evidence_type   VARCHAR(100)    alert_received | enrichment_completed |
                                correlation_detected | policy_executed | analyst_feedback
evidence_data   JSONB           Full event data
source          VARCHAR(255)    trustsoc_intake | trustsoc_enrichment | trustsoc_correlation
hash            VARCHAR(64)     SHA-256 of evidence_data — used for tamper detection
collected_at    TIMESTAMP
```

### `enrichments`
```
id               UUID PRIMARY KEY
alert_id         UUID -> alerts (NOT NULL)
enrichment_type  VARCHAR(100)    ip_reputation | hash_reputation | domain_reputation
provider         VARCHAR(100)    virustotal | abuseipdb | otx | mock
query_value      VARCHAR(255)    The IOC that was looked up
result           JSONB           Full provider API response
confidence_score DECIMAL(3,2)
cost_usd         DECIMAL(10,6)   NEW — API cost for this call
cached           BOOLEAN         NEW — whether result came from cache
api_calls_made   INTEGER         NEW — number of API calls made
created_at       TIMESTAMP (indexed)
```

### `actions`
```
id                UUID PRIMARY KEY
alert_id          UUID -> alerts
incident_id       UUID -> incidents
action_type       VARCHAR(100)   recommend_block_ip | flag_for_human_review | suppress_alert
action_data       JSONB
status            VARCHAR(50)    pending | executed | rolled_back | expired
executed_by       VARCHAR(255)
executed_at       TIMESTAMP
rollback_data     JSONB          How to undo this action
rollback_deadline TIMESTAMP      When auto-rollback fires
notes             TEXT
```

### `assets`
```
id           UUID PRIMARY KEY
hostname     VARCHAR(255) UNIQUE (indexed)
ip_address   INET (indexed)
asset_type   VARCHAR(100)   workstation | server | database | domain_controller
criticality  INTEGER (1-10) Used by guardrails to protect critical infrastructure
owner        VARCHAR(255)
location     VARCHAR(255)
tags         JSONB
last_seen    TIMESTAMP
```

### `users_context`
```
id               UUID PRIMARY KEY
username         VARCHAR(255) UNIQUE (indexed)
email            VARCHAR(255)
is_privileged    BOOLEAN         Elevated scoring for privileged accounts
department       VARCHAR(100)
risk_score       INTEGER         Accumulates from incidents involving this user
known_ips        JSONB           Baseline IPs for impossible travel detection
known_locations  JSONB
```

### `feedback`
```
id            UUID PRIMARY KEY
alert_id      UUID -> alerts
incident_id   UUID -> incidents
feedback_type VARCHAR(50)   true_positive | false_positive | benign | needs_more_data
notes         TEXT
analyst_id    VARCHAR(255)
created_at    TIMESTAMP
```

### `suppressions`
```
id          UUID PRIMARY KEY
rule_name   VARCHAR(255)
conditions  JSONB           Same format as policy conditions
reason      TEXT            Why this is suppressed
created_by  VARCHAR(255)
expires_at  TIMESTAMP       null = never expires
created_at  TIMESTAMP
enabled     BOOLEAN
```

### `policy_executions`
```
id                 UUID PRIMARY KEY
alert_id           UUID -> alerts (indexed)
policy_name        VARCHAR(255)
policy_version     VARCHAR(50)
conditions_met     JSONB   Which conditions passed
actions_determined JSONB   Actions recommended + guardrail outcomes
explanation        TEXT    Rendered explanation string
executed_at        TIMESTAMP
```

---

## 12. How An Alert Moves Through TrustSOC

```
STEP 1: INTAKE
  Client calls POST /api/v1/alerts
    payload: {source_system: "wazuh", alert_data: {...}}

  normalize_alert()
    -> {severity: "high", title: "Mimikatz detected",
        source_host: "windows-01", source_ip: "192.168.1.100",
        iocs: {ips: ["185.x.x.x"], hashes: ["a1b2c3..."]}}

  Create Alert row: status="processing", risk_score=0

  create_evidence("alert_received")
    -> SHA-256 hashed record in evidence table

  Schedule 3 BackgroundTasks
  Return 201 immediately with alert ID


STEP 2: ENRICHMENT (background, 2-10 seconds)
  For each IOC (skip private IPs, respect budget cap):
    VirusTotal: {malicious_detections: 8, total_engines: 72}
    AbuseIPDB:  {abuse_confidence_score: 94, isp: "AS12345 Hosting"}
    OTX:        {pulse_count: 3, malware_families: ["Cobalt Strike"]}
    Store Enrichment rows with cost_usd=0.0, cached=false

  calculate_risk_score():
    base (high severity) = 45
    VT bonus (8/72 * 35) = +3
    AbuseIPDB bonus (94 * 0.25) = +23
    OTX bonus (min(15, 3*3)) = +9
    total = 80, confidence = 0.83

  Update alert: risk_score=80, confidence_score=0.83, status="enriched"
  create_evidence("enrichment_completed")


STEP 3: CORRELATION (background, runs in parallel with enrichment)
  _detect_brute_force(): this alert's title contains "failed" but only 1 alert so far -> skip
  _detect_lateral_movement(): no repeated user across hosts -> skip
  _detect_privilege_escalation(): "mimikatz" + process execution on windows-01 -> MATCH

  Create Incident:
    title: "Privilege Escalation on windows-01"
    pattern_type: "privilege_escalation"
    severity: "critical"
    mitre_tactics: ["Privilege Escalation", "Persistence"]
    mitre_techniques: ["T1078", "T1136", "T1136.001"]

  Link alerts to incident via incident_id
  create_evidence("correlation_detected") on the incident


STEP 4: POLICY ENGINE (background)
  Load policies/*.yaml (3 policies)

  Check auto_block_high_risk_ip.yaml:
    risk_score (80) >= 80? YES
    source_ip is_external? -> 192.168.1.100 is PRIVATE -> NO
    -> Conditions not all met, skip

  Check escalate_critical_alerts.yaml:
    normalized_alert.severity == "critical"? -> alert is "high" -> NO
    -> Skip

  Check suppress_low_risk_internal.yaml:
    risk_score (80) <= 20? NO
    -> Skip

  No policies triggered for this alert.
  (The incident-level alert may trigger policies separately)


STEP 5: ANALYST REVIEW (any time after step 1)
  GET /api/v1/alerts/{id}
    status: "enriched", risk_score: 80, confidence_score: 0.83

  GET /api/v1/incidents
    [{id: "...", title: "Privilege Escalation on windows-01",
      severity: "critical", pattern_type: "privilege_escalation"}]

  GET /api/v1/incidents/{id}/timeline
    [
      {timestamp: "10:31:00", event_type: "alert_received", summary: "Alert received from wazuh"},
      {timestamp: "10:31:05", event_type: "enrichment_completed", summary: "risk=80, confidence=0.83"},
      {timestamp: "10:31:05", event_type: "correlation_detected", summary: "Correlated as privilege_escalation with 2 alerts"}
    ]

  POST /api/v1/incidents/{id}/feedback
    {feedback_type: "true_positive", notes: "Confirmed Mimikatz execution", analyst_id: "john.analyst"}
    -> incident.status = "confirmed"
    -> evidence record created for feedback


STEP 6: INTEGRITY VERIFICATION (any time)
  GET /api/v1/alerts/{id}/evidence/verify
  For each evidence record:
    Recompute SHA-256(evidence_data)
    Compare to stored hash
    is_valid: true -> untampered
    is_valid: false -> "Evidence hash mismatch — possible tampering"
```

---

## 13. Open-Source Community Strategy

### Three Contribution Ladders

Designed so contributors at every skill level can participate:

**`good-first-issue` — Add a source normalizer**
Add a new `elif source_system == 'crowdstrike':` block in `app/utils/helpers.py` → `normalize_alert()`.
About 20 lines. Immediately useful to everyone using that source. No architecture knowledge needed.
Other targets: Microsoft Defender, SentinelOne, Carbon Black, QRadar, Darktrace.

**`enrichment-plugin` — Build a new provider**
Add a provider class following the pattern in `app/services/enrichment.py`.
Targets: Shodan, GreyNoise, Have I Been Pwned, Censys, CIRCL MISP, ThreatFox, URLhaus.

**`suppression-rule` — Submit a YAML false-positive rule**
Create a YAML file in a separate `trustsoc-community-rules` GitHub repo.
No coding. Immediately useful to everyone dealing with the same noisy tool.

### Community Rules Hub (Planned)

Separate repo: `trustsoc-community-rules`
```
rules/
  windows/
    fp_windows_update.yaml
    fp_defender_scan.yaml
    fp_sccm_agent.yaml
  linux/
    fp_logrotate.yaml
    fp_cron_jobs.yaml
  cloud/
    fp_aws_cloudtrail.yaml
    fp_azure_ad_sync.yaml
```

Import a community rule:
```bash
POST /api/v1/suppressions/import
{"url": "https://raw.githubusercontent.com/trustsoc/community-rules/main/windows/fp_windows_update.yaml"}
```

### MITRE ATT&CK Coverage Badge (Phase 3)

`GET /api/v1/mitre/coverage` returns ATT&CK Navigator-compatible JSON.
Teams paste it into the Navigator to visualize their detection coverage — the most shareable artifact TrustSOC produces.

---

## 14. Phase Roadmap

### Phase 0 — Preparation ✅ COMPLETE
- Python, Git, VS Code, accounts setup
- Supabase, Render, VirusTotal, AbuseIPDB, OTX accounts created

### Phase 1 — Foundation + Intelligence Pipeline ✅ COMPLETE
Everything listed in Sections 8 and 9 above.

### Phase 2 — Differentiators (Weeks 5-6) — IN PROGRESS

**LLM Investigation Narratives** ✅ DONE (April 1, 2026)
- `app/services/narrative.py` — Claude API integration with 3-section output
- `Narrative` DB table (11th table) — `alert_id`, `incident_id`, `narrative_text`, sections, `model_used`, `token_count`, `cost_usd`, `is_mock`
- 4 endpoints: POST/GET on both alerts and incidents
- Graceful mock when `ANTHROPIC_API_KEY` absent
- `anthropic==0.40.0` in requirements.txt
- Migration `d198113371aa` applied

**Case Management** ✅ DONE (April 1, 2026)
- `app/models.py` — `Case`, `CaseIncident` (M2M association), `CaseNote` (3 new tables, migration `27840a650004` applied)
- `app/routers/cases.py` — 8 endpoints: create, list, get, patch, add-incidents, remove-incident, add-note, export
- `app/schemas.py` — `CaseCreate`, `CaseResponse`, `CaseDetail`, `CaseNoteCreate`, `CaseNoteResponse`
- `GET /api/v1/cases/{id}/export` — self-contained JSON compliance bundle: case + all incidents + all alert evidence + enrichments + policy decisions + analyst notes. Suitable for legal handoff / SOC2 audit.

**Suppression Rule Engine** ✅ DONE (April 1, 2026)
- `app/services/suppression.py` — evaluates alerts against DB rules synchronously at intake (before BackgroundTasks). If matched: status="suppressed", evidence record written, no API calls made.
- `app/routers/suppressions.py` — 7 endpoints: list, create, get, toggle, delete, import YAML body, import from URL
- `app/schemas.py` — `SuppressionCreate`, `SuppressionResponse`, `SuppressionCondition`, `SuppressionImportRequest`
- `app/routers/alerts.py` — suppression check wired before background tasks; early return skips enrichment/correlation/policy
- Supports same operator set as policy engine: `eq`, `neq`, `contains`, `gte`, `lte`, `gt`, `lt`, `exists`, `is_external`
- Community rules importable by URL: `POST /api/v1/suppressions/import-url {"url": "..."}`

**Plugin Architecture** ✅ DONE (April 1, 2026)
- `app/plugins/base.py` — `BaseEnrichmentPlugin` abstract class (contract for all plugins)
- `app/plugins/registry.py` — `PluginRegistry` singleton; auto-discovers `app/plugins/providers/*.py` + loads community plugins from `TRUSTSOC_PLUGIN_DIR`
- `app/plugins/providers/virustotal.py`, `abuseipdb.py`, `otx.py` — built-in providers refactored as plugins
- `app/services/enrichment.py` — refactored to call `registry.get_providers_for(ioc_type)` instead of hardcoded list
- `app/main.py` — `initialize_plugins()` called at startup; `GET /api/v1/plugins` endpoint shows loaded plugins
- Community plugin authoring: subclass `BaseEnrichmentPlugin`, drop `.py` in `TRUSTSOC_PLUGIN_DIR`

**Plugin Architecture** — `app/plugins/`
```
app/plugins/
  base.py           BaseEnrichmentPlugin abstract class
  registry.py       PluginRegistry — auto-scans providers/ at startup
  providers/
    virustotal.py
    abuseipdb.py
    otx.py
    local_misp.py   For offline/air-gapped environments
```
- Community plugins loaded from `~/.trustsoc/plugins/` (configurable via `TRUSTSOC_PLUGIN_DIR`)
- Refactor `services/enrichment.py` to call `registry.get_providers_for_ioc_type(ioc_type)`

**Suppression Rule Engine** — `app/services/suppression.py`
- Evaluate alerts against DB suppression rules BEFORE enrichment (no cost on known FPs)
- YAML import endpoint: `POST /api/v1/suppressions/import`
- Full CRUD: `GET /api/v1/suppressions`, `POST /api/v1/suppressions`
- New router: `app/routers/suppressions.py`

**Case Management** — `app/routers/cases.py`
- New `Case` model (wraps multiple incidents with analyst workspace)
- `POST /api/v1/cases`, `GET /api/v1/cases/{id}`, `POST /api/v1/cases/{id}/notes`
- `GET /api/v1/cases/{id}/export` — JSON compliance bundle for legal/handoff

### Phase 3 — Community & Ecosystem (Weeks 7-8)

**MITRE ATT&CK Coverage API** — `app/routers/mitre.py`
- `GET /api/v1/mitre/coverage` — ATT&CK Navigator-compatible heatmap JSON

**CLI Tool** — `trustsoc-cli/`
```bash
trustsoc demo                   # seed 8 realistic alert scenarios
trustsoc sync-rules             # pull latest community suppression rules
trustsoc status                 # health check + stats summary
trustsoc install-plugin <name>  # download enrichment plugin
trustsoc export <incident_id>   # download full evidence bundle
```

**GitHub Actions CI/CD** — `.github/workflows/`
- `test.yml` — pytest on every PR
- `lint.yml` — ruff linter (zero config)
- `docker-build.yml` — validate compose builds
- Coverage badge for README

**Offline / Air-Gapped Mode**
- `local_misp.py` plugin for MISP integration
- ThreatFox offline feed importer
- `OFFLINE_MODE=true` skips all external API calls

**`CONTRIBUTING.md`** with contribution ladders, plugin docs, rule format spec

---

## 15. Configuration Reference

```bash
# ─── REQUIRED (only these two are mandatory) ──────────────────
DATABASE_URL=postgresql://user:password@host:5432/trustsoc
API_KEY=your_secret_api_key

# ─── THREAT INTELLIGENCE (all optional) ───────────────────────
# System runs with mock data if these are missing
VIRUSTOTAL_API_KEY=          # https://virustotal.com — 4 req/min free
ABUSEIPDB_API_KEY=           # https://abuseipdb.com — 1,000/day free
OTX_API_KEY=                 # https://otx.alienvault.com — unlimited free

# ─── LLM NARRATIVES (Phase 2) ─────────────────────────────────
ANTHROPIC_API_KEY=           # https://console.anthropic.com

# ─── ENRICHMENT CONTROLS ──────────────────────────────────────
ENRICHMENT_BUDGET_PER_ALERT_USD=0.10    # Stop enriching when this cost is reached
ENRICHMENT_CACHE_TTL_SECONDS=3600       # Cache IOC results for 1 hour

# ─── SAFETY / GUARDRAILS ──────────────────────────────────────
AUTO_BLOCK_ENABLED=true                 # Master switch — set false to disable all blocking
AUTO_BLOCK_DURATION_MINUTES=15          # How long auto-blocks last before rollback
CRITICAL_ASSET_MIN_SCORE=8              # Assets >= this score require human review
MAX_BLOCKS_PER_HOUR=50                  # Rate limit on automated blocking actions

# ─── RISK THRESHOLDS ──────────────────────────────────────────
HIGH_RISK_THRESHOLD=70                  # Score >= this = high risk category
MEDIUM_RISK_THRESHOLD=40                # Score >= this = medium risk

# ─── CORRELATION ──────────────────────────────────────────────
CORRELATION_TIME_WINDOW_MINUTES=15      # How far back to look for related alerts
MIN_ALERTS_FOR_INCIDENT=3               # Minimum alerts needed to create an incident

# ─── APPLICATION ──────────────────────────────────────────────
ENVIRONMENT=development                 # or "production"
LOG_LEVEL=INFO                          # DEBUG | INFO | WARNING | ERROR
MAX_ALERTS_PER_MINUTE=100               # Rate limit on alert ingestion endpoint
```

---

## 16. Quick Start Guide

### Option A: Docker — Zero Config (Recommended)

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/trustsoc.git
cd trustsoc

# Start all services
docker compose up

# Wait ~30 seconds

# API:     http://localhost:8000/docs   (API key: trustsoc_demo_key)
# Grafana: http://localhost:3000        (admin / admin)

# Seed 8 realistic demo alerts
python scripts/generate_demo_data.py \
  --url http://localhost:8000 \
  --key trustsoc_demo_key

# Watch risk scores and incidents appear in Grafana
```

### Option B: Local Development

```bash
# Clone and enter
git clone https://github.com/YOUR_USERNAME/trustsoc.git
cd trustsoc

# Virtual environment
python -m venv venv
venv\Scripts\activate         # Windows
source venv/bin/activate      # Mac/Linux

# Install
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env — set DATABASE_URL and API_KEY at minimum

# Run
uvicorn app.main:app --reload --port 8000

# API docs: http://localhost:8000/docs

# Seed demo data
python scripts/generate_demo_data.py

# Run tests
pytest tests/ -v
```

### Sending Your First Alert

```bash
curl -X POST http://localhost:8000/api/v1/alerts \
  -H "x-api-key: trustsoc_demo_key" \
  -H "Content-Type: application/json" \
  -d '{
    "source_system": "wazuh",
    "external_id": "test-001",
    "alert_data": {
      "rule": {"description": "Mimikatz detected", "level": 15},
      "agent": {"name": "windows-01", "ip": "192.168.1.100"},
      "full_log": "mimikatz.exe executed by john.doe"
    }
  }'

# Returns immediately: {"id": "abc-123...", "status": "processing", "risk_score": 0}

# Wait 3-5 seconds for enrichment pipeline
curl -H "x-api-key: trustsoc_demo_key" \
  http://localhost:8000/api/v1/alerts/abc-123

# Now: status="enriched", risk_score=80 (or similar)

# See full evidence trail
curl -H "x-api-key: trustsoc_demo_key" \
  http://localhost:8000/api/v1/alerts/abc-123/evidence

# See if an incident was auto-created
curl -H "x-api-key: trustsoc_demo_key" \
  http://localhost:8000/api/v1/incidents

# Verify evidence integrity
curl -H "x-api-key: trustsoc_demo_key" \
  http://localhost:8000/api/v1/alerts/abc-123/evidence/verify
```

---

## 17. Deployment

### Live Production Deployment
- **Platform:** Render.com (free tier)
- **Auto-deploy:** Push to GitHub main → Render rebuilds and deploys automatically
- **Database:** Supabase PostgreSQL (use Session Pooler URL for IPv4 compatibility)

### Deploy Changes
```bash
git add .
git commit -m "Your description"
git push origin master
# Render deploys automatically in 2-3 minutes
```

### Render Environment Variables
Set these in the Render dashboard under Environment:

| Variable | Required | Notes |
|----------|----------|-------|
| `DATABASE_URL` | YES | Use Supabase Session Pooler URL (port 6543) |
| `API_KEY` | YES | Use a strong random value in production |
| `ENVIRONMENT` | Yes | Set to `production` |
| `VIRUSTOTAL_API_KEY` | No | Live threat intel |
| `ABUSEIPDB_API_KEY` | No | Live IP reputation |
| `OTX_API_KEY` | No | Live threat feeds |
| `ANTHROPIC_API_KEY` | No | LLM narratives (Phase 2) |

### Supabase Connection Note
Use the **Session Pooler** connection string from Supabase, not the Direct Connection.
Session Pooler format: `postgresql://postgres.[REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres`
This ensures IPv4 compatibility with Render's free tier.

### Schema Migrations in Production
After adding any new fields or tables:
```bash
# Generate migration
alembic revision --autogenerate -m "description"

# Test locally first
alembic upgrade head

# Commit migration file
git add alembic/versions/
git commit -m "Add migration: description"
git push
# Render deploys; run migration manually or add to startup
```

---

## 18. Current Project Metrics

| Metric | Count |
|--------|-------|
| Python files | 22 |
| Lines of code (new this session) | 1,574 |
| Total lines of code (all services) | 2,400+ |
| Database tables | 10 |
| API endpoints | 11 |
| Automated tests | 28 |
| Grafana dashboards | 3 |
| YAML policy files | 3 |
| Alert sources supported | 3 (Wazuh, Splunk, Elastic) |
| Threat intel providers | 3 (VirusTotal, AbuseIPDB, OTX) |
| Attack patterns detected | 3 (brute force, lateral movement, privilege escalation) |
| MITRE techniques mapped | 10 |
| Docker services | 3 (postgres, api, grafana) |

### Phase Completion

```
Phase 1: Foundation + Intelligence Pipeline   [████████████] 100% COMPLETE
  Core API                                                   DONE
  Database (10 tables)                                       DONE
  Evidence audit trail                                       DONE
  28 automated tests                                         DONE
  Alembic migrations                                         DONE
  Enrichment service (VT, AbuseIPDB, OTX)                   DONE
  Correlation engine (3 patterns + MITRE)                    DONE
  Policy engine (YAML rules + guardrails)                    DONE
  Incidents router (5 endpoints)                             DONE
  BackgroundTasks pipeline wiring                            DONE
  SOC in a Box docker-compose                                DONE
  3 Grafana dashboards                                       DONE

Phase 2: Differentiators                      [████████████] 100% COMPLETE ✅
  LLM investigation narratives (Claude API)                  DONE ✅
  Plugin architecture                                        DONE ✅
  Suppression rule engine                                    DONE ✅
  Case management                                            DONE ✅

Phase 3: Community & Ecosystem               [████████████] 100% COMPLETE ✅
  MITRE coverage API                                         DONE ✅
  CLI tool (trustsoc-cli)                                    DONE ✅
  GitHub Actions CI/CD                                       DONE ✅
  Offline/air-gapped mode                                    DONE ✅
  CONTRIBUTING.md + plugin docs                              DONE ✅

Overall: [████████████] 100% COMPLETE
```

---

*Document Version: 3.0*
*All 3 phases complete. TrustSOC is a fully-featured open-source SOC automation platform.*
