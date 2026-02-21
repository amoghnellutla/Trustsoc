"""
Demo data generator for TrustSOC.
Sends realistic security alerts so you can demo without a real Wazuh setup.

Usage:
    python scripts/generate_demo_data.py

Env vars (optional):
    TRUSTSOC_URL   = http://localhost:8000
    TRUSTSOC_KEY   = trustsoc_dev_key_change_later
    TRUSTSOC_COUNT = 1   (how many rounds of templates to send)
"""

from __future__ import annotations

import os
import random
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

import requests


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_URL = os.getenv("TRUSTSOC_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.getenv("TRUSTSOC_KEY", "").strip()
COUNT = int(os.getenv("TRUSTSOC_COUNT", "1"))

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json",
}

# In your app/config.py, MAX_ALERTS_PER_MINUTE defaults to 100
# 0.7s delay ~= 85/min, safe.
REQUEST_DELAY_SECONDS = 0.7

# If you want to treat this as "placeholder / invalid for demos", add it here.
# In your case, you said your .env has: trustsoc_dev_key_change_later
# So we should ALLOW that. We only block truly missing/empty.
BLOCK_IF_KEYS = {
    "",
    "trustsoc_dev_key_change_this_in_production",
    "trustsoc_dev_key_change_this_in_production ",
}


# ---------------------------------------------------------------------------
# Alert templates
# ---------------------------------------------------------------------------

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


ALERT_TEMPLATES: List[Dict[str, Any]] = [
    {
        "label": "Mimikatz Execution",
        "source_system": "wazuh",
        "alert_data": {
            "rule": {"description": "Mimikatz Usage Detected", "level": 15, "id": "100002"},
            "agent": {"name": "LAPTOP-HR-042", "ip": "192.168.1.42"},
            "data": {
                "win": {
                    "eventdata": {
                        "originalFileName": "mimikatz.exe",
                        "commandLine": ".\\mimikatz.exe sekurlsa::logonpasswords",
                        "hashes": "SHA256=fc81b8a524eeb08e88f7c2b7e2c6ff18e7e43a63f3b8d0a8e88e1234567890ab",
                        "user": "john.doe",
                        "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    }
                }
            },
            "full_log": "Process mimikatz.exe executed - credential dumping attempt",
            "timestamp": now_utc(),
        },
    },
    {
        "label": "SSH Brute Force",
        "source_system": "wazuh",
        "alert_data": {
            "rule": {"description": "Multiple SSH authentication failures", "level": 10, "id": "5763"},
            "agent": {"name": "web-server-01", "ip": "10.0.1.15"},
            "data": {"srcip": "45.227.254.5", "dstuser": "root", "protocol": "ssh"},
            "full_log": "sshd: Failed password for root from 45.227.254.5 port 51234 ssh2",
            "timestamp": now_utc(),
        },
    },
    {
        "label": "Malware Download",
        "source_system": "elastic",
        "alert_data": {
            "rule": {"name": "Suspicious File Download", "severity": "high"},
            "host": {"name": "workstation-fin-07"},
            "source": {"ip": "185.234.218.23"},
            "file": {
                "name": "invoice_2024.exe",
                "hash": {"sha256": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"},
                "size": 2_457_600,
            },
            "@timestamp": now_utc(),
        },
    },
    {
        "label": "New Admin Account Created",
        "source_system": "wazuh",
        "alert_data": {
            "rule": {
                "description": "New user added to administrators group",
                "level": 12,
                "id": "18152",
                "mitre": {"technique": ["T1136"], "tactic": ["Persistence"]},
            },
            "agent": {"name": "DC-PRIMARY-01", "ip": "10.0.0.5"},
            "data": {
                "win": {
                    "eventdata": {
                        "targetUserName": "svc_backup_new",
                        "targetSid": "S-1-5-21-xxx",
                        "memberName": "Administrators",
                        "subjectUserName": "john.doe",
                    }
                }
            },
            "full_log": "User svc_backup_new added to Administrators group by john.doe",
            "timestamp": now_utc(),
        },
    },
    {
        "label": "Suspicious PowerShell Execution",
        "source_system": "splunk",
        "alert_data": {
            "search_name": "PowerShell Encoded Command Detected",
            "severity": "high",
            "host": "WORKSTATION-DEV-12",
            "src_ip": "192.168.2.55",
            "message": "PowerShell encoded command executed",
            "CommandLine": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA",
            "User": "jane.smith",
            "_time": now_utc(),
        },
    },
    {
        "label": "Potential Data Exfiltration",
        "source_system": "elastic",
        "alert_data": {
            "rule": {"name": "Abnormal Outbound Data Transfer", "severity": "high"},
            "host": {"name": "db-server-02"},
            "destination": {"ip": "104.21.66.114", "bytes": 524_288_000, "country": "RU"},
            "source": {"ip": "10.0.2.20", "port": 443},
            "network": {"protocol": "https"},
            "@timestamp": now_utc(),
        },
    },
    {
        "label": "Ransomware File Activity",
        "source_system": "wazuh",
        "alert_data": {
            "rule": {"description": "Ransomware-like file modification detected", "level": 15, "id": "100050"},
            "agent": {"name": "LAPTOP-FINANCE-03", "ip": "192.168.1.78"},
            "syscheck": {
                "path": "C:\\Users\\Documents",
                "event": "modified",
                "changed_attributes": ["content", "mtime"],
                "changes": 847,
            },
            "full_log": "847 files modified in 60 seconds in Documents folder — possible encryption",
            "timestamp": now_utc(),
        },
    },
    {
        "label": "Impossible Travel Detected",
        "source_system": "elastic",
        "alert_data": {
            "rule": {"name": "Impossible Travel Login", "severity": "medium"},
            "user": {"name": "sarah.jones"},
            "source": {"ip": "102.89.34.56", "geo": {"country": "NG", "city": "Lagos"}},
            "event": {"action": "user_login", "outcome": "success"},
            "previous_login": {
                "ip": "71.45.23.89",
                "geo": {"country": "US", "city": "New York"},
                "minutes_ago": 12,
            },
            "@timestamp": now_utc(),
        },
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def send_alert(template: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    payload = {
        "source_system": template["source_system"],
        "external_id": f"demo-{random.randint(10000, 99999)}",
        "alert_data": template["alert_data"],
    }

    try:
        resp = requests.post(
            f"{BASE_URL}/api/v1/alerts",
            json=payload,
            headers=HEADERS,
            timeout=10,
        )

        # Helpful error body on failures
        if resp.status_code >= 400:
            try:
                err = resp.json()
            except Exception:
                err = resp.text
            raise requests.HTTPError(f"{resp.status_code} {resp.reason} - {err}", response=resp)

        return resp.json()

    except requests.RequestException as exc:
        print(f"    Request failed: {exc}")
        return None


def print_banner() -> None:
    print("\n" + "=" * 70)
    print("TrustSOC - Demo Data Generator")
    print("=" * 70)
    print(f"Target: {BASE_URL}")
    print(f"Templates per round: {len(ALERT_TEMPLATES)}")
    print(f"Rounds: {COUNT}")
    print("=" * 70 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print_banner()

    # Fail fast (prevents guaranteed 401 mistakes)
    if API_KEY in BLOCK_IF_KEYS:
        print("ERROR: TRUSTSOC_KEY is not set (or still placeholder).")
        print("Fix (PowerShell, Terminal 2):")
        print('  $env:TRUSTSOC_KEY = "trustsoc_dev_key_change_later"   # or your real .env API_KEY')
        print("  python scripts\\generate_demo_data.py")
        return

    # Connectivity check
    try:
        health = requests.get(f"{BASE_URL}/health", timeout=5)
        health.raise_for_status()
        print("OK: TrustSOC API is reachable (/health)\n")
    except Exception as exc:
        print(f"ERROR: Cannot reach TrustSOC at {BASE_URL}: {exc}")
        print("Fix: Start server in Terminal 1:")
        print("  uvicorn app.main:app --reload --port 8000")
        return

    created_ids: List[str] = []

    for round_idx in range(1, COUNT + 1):
        shuffled = ALERT_TEMPLATES[:]
        random.shuffle(shuffled)

        print(f"--- Round {round_idx}/{COUNT} ---")
        for i, template in enumerate(shuffled, 1):
            label = template["label"]
            print(f"[{i:02d}/{len(shuffled)}] Sending: {label} ...", end=" ", flush=True)

            result = send_alert(template)
            if result and "id" in result:
                created_ids.append(str(result["id"]))
                print(f"OK  ID: {str(result['id'])[:8]}...")
            else:
                print("FAILED")

            time.sleep(REQUEST_DELAY_SECONDS)

        print()

    print("-" * 70)
    print(f"Created alerts: {len(created_ids)}")
    if created_ids:
        sample_id = created_ids[0]
        print("\nTry these endpoints:")
        print(f"GET {BASE_URL}/api/v1/alerts")
        print(f"GET {BASE_URL}/api/v1/alerts/{sample_id}")
        print(f"GET {BASE_URL}/api/v1/alerts/{sample_id}/evidence")
        print(f"GET {BASE_URL}/api/v1/alerts/{sample_id}/evidence/verify")
        print(f"GET {BASE_URL}/api/v1/stats")
    print(f"\nSwagger: {BASE_URL}/docs")
    print("-" * 70 + "\n")


if __name__ == "__main__":
    main()