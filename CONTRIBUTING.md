# Contributing to TrustSOC

TrustSOC is open-source and welcomes contributions at every skill level.
Three contribution ladders — pick the one that fits where you are.

---

## Ladder 1: good-first-issue — Add a source normalizer

**Difficulty:** Beginner (~20 lines of Python)
**Impact:** Immediately useful to everyone using that source system

### How

Open `app/utils/helpers.py` → find `normalize_alert()` → add a new `elif` block:

```python
elif source_system == "crowdstrike":
    return {
        "title": data.get("name", "Unknown"),
        "severity": _map_severity(data.get("severity_name", "medium")),
        "source_host": data.get("device", {}).get("hostname"),
        "source_ip": data.get("device", {}).get("external_ip"),
        "user": data.get("user_name"),
        "iocs": extract_iocs(data),
        "raw": data,
    }
```

### Open targets

| Source | Notes |
|--------|-------|
| Microsoft Defender | `AlertEvidence`, `AlertInfo` schema |
| SentinelOne | `threatInfo.threatName`, `agentDetectionInfo` |
| Carbon Black | `cb.threathunter.*` events |
| QRadar | `offense_id`, `categories` |
| Darktrace | `model.name`, `device.hostname` |

### Testing your normalizer

```bash
pytest tests/ -v -k "test_normalize"
```

---

## Ladder 2: enrichment-plugin — Build a new provider

**Difficulty:** Intermediate (~60 lines of Python)
**Impact:** Adds a new threat intel source available to everyone

### How

1. Create `app/plugins/providers/yourprovider.py`
2. Subclass `BaseEnrichmentPlugin` from `app/plugins/base.py`
3. Implement `enrich(ioc_value, ioc_type) -> Optional[Dict]`
4. Drop the file — it auto-loads at startup

### Template

```python
from typing import Any, Dict, Optional
import requests
from app.plugins.base import BaseEnrichmentPlugin
from app.config import settings

class YourProviderPlugin(BaseEnrichmentPlugin):
    name = "yourprovider"
    supported_types = ["ip", "domain"]   # what IOC types you handle
    cost_per_call_usd = 0.0

    def enrich(self, ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        api_key = settings.YOUR_PROVIDER_API_KEY
        if not api_key:
            return None  # skip gracefully — never crash
        try:
            resp = requests.get(
                f"https://api.yourprovider.com/v1/check/{ioc_value}",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=10,
            )
            if resp.status_code == 404:
                return {"found": False, "provider": self.name}
            resp.raise_for_status()
            data = resp.json()
            return {
                "found": True,
                "provider": self.name,
                "summary": data.get("verdict", "unknown"),
                # ... add fields relevant to your provider
            }
        except requests.RequestException:
            return None  # log and skip on errors
```

### Add API key to config

In `app/config.py` add:
```python
YOUR_PROVIDER_API_KEY: Optional[str] = None
```

### Open targets

| Provider | Docs | IOC types |
|----------|------|-----------|
| Shodan | shodan.io/api | ip |
| GreyNoise | greynoise.io/docs | ip |
| CIRCL MISP | circl.lu/services/misp-feed | hash, ip |
| ThreatFox | threatfox.abuse.ch | hash, domain, ip |
| URLhaus | urlhaus-api.abuse.ch | url, domain |
| Have I Been Pwned | haveibeenpwned.com/api | email |
| Censys | search.censys.io/api | ip, domain |

---

## Ladder 3: suppression-rule — Submit a false-positive rule

**Difficulty:** No coding required
**Impact:** Reduces noise for everyone dealing with the same tool

### How

Create a YAML file in the community rules repo:
`https://github.com/trustsoc/community-rules`

### Format

```yaml
rule_name: fp_windows_defender_scan
reason: "Windows Defender scheduled scan — safe, triggers daily on managed endpoints"
expires_after_days: 365
conditions:
  - field: normalized_alert.title
    operator: contains
    value: "Windows Defender"
  - field: normalized_alert.severity
    operator: eq
    value: low
```

### Supported operators

| Operator | Description |
|----------|-------------|
| `eq` | Exact match (case-insensitive) |
| `neq` | Not equal |
| `contains` | Substring match |
| `gte` / `lte` | Numeric ≥ / ≤ |
| `gt` / `lt` | Numeric > / < |
| `exists` | Field is not null |
| `is_external` | IP is not RFC1918 private |

### Supported fields

```
source_system
normalized_alert.severity
normalized_alert.title
normalized_alert.source_ip
normalized_alert.source_host
normalized_alert.user
risk_score
```

### File placement in the community repo

```
rules/
  windows/      — Windows-specific false positives
  linux/        — Linux/Unix
  cloud/        — AWS, Azure, GCP
  network/      — Firewall, IDS/IPS
  macos/        — macOS endpoint
```

---

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/trustsoc.git
cd trustsoc
python -m venv venv
source venv/bin/activate      # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env
# Edit .env — set DATABASE_URL and API_KEY at minimum
python -m alembic upgrade head
uvicorn app.main:app --reload
pytest tests/ -v
```

## Pull request checklist

- [ ] `pytest tests/ -v` passes
- [ ] No new failing lint warnings (`ruff check app/`)
- [ ] New provider: includes graceful `return None` when API key absent
- [ ] New normalizer: tested with at least one real payload sample
- [ ] New suppression rule: includes `reason` field explaining why it's a FP

## Questions?

Open an issue at `https://github.com/YOUR_USERNAME/trustsoc/issues`
