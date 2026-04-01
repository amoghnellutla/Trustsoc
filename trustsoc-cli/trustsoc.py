#!/usr/bin/env python3
"""
trustsoc — CLI tool for TrustSOC API.

Commands:
  demo          Seed 8 realistic alert scenarios
  sync-rules    Pull latest community suppression rules from a GitHub URL
  status        Health check + system stats summary
  export        Download full evidence bundle for an alert or case
  plugins       List loaded enrichment plugins

Usage:
  python trustsoc-cli/trustsoc.py --url http://localhost:8000 --key trustsoc_demo_key <command>

Environment variables (override flags):
  TRUSTSOC_URL   Base URL of TrustSOC API
  TRUSTSOC_KEY   API key
"""

import argparse
import json
import os
import sys
import time
from typing import Optional

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _client(base_url: str, api_key: str):
    session = requests.Session()
    session.headers.update({"x-api-key": api_key, "Content-Type": "application/json"})
    session.base_url = base_url.rstrip("/")
    return session


def _get(session, path: str):
    resp = session.get(f"{session.base_url}{path}")
    resp.raise_for_status()
    return resp.json()


def _post(session, path: str, data: dict):
    resp = session.post(f"{session.base_url}{path}", json=data)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status(session, _args):
    health = _get(session, "/health")
    stats = _get(session, "/api/v1/stats")
    plugins = _get(session, "/api/v1/plugins")
    print(f"Status:          {health['status'].upper()}")
    print(f"Total alerts:    {stats['total_alerts']}  (24h: {stats['alerts_24h']})")
    print(f"Total incidents: {stats['total_incidents']}  (24h: {stats['incidents_24h']})")
    print(f"High-risk open:  {stats['high_risk_open']}")
    print(f"Plugins loaded:  {plugins['total_plugins']}  ({', '.join(p['name'] for p in plugins['plugins'])})")


def cmd_plugins(session, _args):
    data = _get(session, "/api/v1/plugins")
    print(f"{'Plugin':<20} {'IOC Types':<30} {'Cost/call'}")
    print("-" * 60)
    for p in data["plugins"]:
        print(f"{p['name']:<20} {', '.join(p['types']):<30} ${p['cost_per_call']:.4f}")
    print(f"\nTotal: {data['total_plugins']} plugin(s)")


def cmd_demo(session, args):
    scenarios = [
        {
            "source_system": "wazuh",
            "external_id": "demo-mimikatz-001",
            "alert_data": {
                "rule": {"description": "Mimikatz credential dumping detected", "level": 15},
                "agent": {"name": "windows-01", "ip": "192.168.1.100"},
                "full_log": "mimikatz.exe executed by john.doe — lsass memory access detected",
            },
        },
        {
            "source_system": "wazuh",
            "external_id": "demo-ssh-brute-001",
            "alert_data": {
                "rule": {"description": "SSH brute force attack", "level": 10},
                "agent": {"name": "linux-web-01", "ip": "192.168.1.50"},
                "full_log": "Failed password for root from 185.220.101.45 port 54321",
            },
        },
        {
            "source_system": "wazuh",
            "external_id": "demo-ssh-brute-002",
            "alert_data": {
                "rule": {"description": "SSH brute force attack", "level": 10},
                "agent": {"name": "linux-web-01", "ip": "192.168.1.50"},
                "full_log": "Failed password for admin from 185.220.101.45 port 54322",
            },
        },
        {
            "source_system": "wazuh",
            "external_id": "demo-ssh-brute-003",
            "alert_data": {
                "rule": {"description": "SSH authentication failure", "level": 10},
                "agent": {"name": "linux-web-01", "ip": "192.168.1.50"},
                "full_log": "authentication failure from 185.220.101.45",
            },
        },
        {
            "source_system": "splunk",
            "external_id": "demo-malware-dl-001",
            "alert_data": {
                "search_name": "Suspicious File Download",
                "severity": "high",
                "src_ip": "192.168.1.200",
                "dest_ip": "198.51.100.23",
                "file_name": "payload.exe",
                "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd",
            },
        },
        {
            "source_system": "wazuh",
            "external_id": "demo-new-admin-001",
            "alert_data": {
                "rule": {"description": "New admin account created", "level": 12},
                "agent": {"name": "dc-01", "ip": "192.168.1.10"},
                "full_log": "net user backdoor P@ssw0rd /add && net localgroup administrators backdoor /add",
            },
        },
        {
            "source_system": "elastic",
            "external_id": "demo-powershell-001",
            "alert_data": {
                "message": "Suspicious PowerShell execution",
                "host": {"name": "windows-02", "ip": "192.168.1.101"},
                "process": {"name": "powershell.exe", "args": "-EncodedCommand SQBFAFgA..."},
                "severity": "high",
            },
        },
        {
            "source_system": "wazuh",
            "external_id": "demo-ransomware-001",
            "alert_data": {
                "rule": {"description": "Ransomware file encryption activity", "level": 15},
                "agent": {"name": "fileserver-01", "ip": "192.168.1.75"},
                "full_log": "Multiple files renamed with .locked extension — possible ransomware",
            },
        },
    ]

    count = min(getattr(args, "count", len(scenarios)), len(scenarios))
    url = getattr(args, "url", None)
    print(f"Seeding {count} demo alert(s) to {session.base_url}...")

    for i, scenario in enumerate(scenarios[:count]):
        try:
            result = _post(session, "/api/v1/alerts", scenario)
            print(f"  [{i+1}/{count}] {scenario['external_id']} → id={result['id'][:8]}... status={result['status']}")
            time.sleep(0.3)
        except Exception as exc:
            print(f"  [{i+1}/{count}] FAILED: {exc}")

    print(f"\nDone. Wait ~5s then check: GET /api/v1/incidents")


def cmd_sync_rules(session, args):
    urls = getattr(args, "urls", None) or [
        "https://raw.githubusercontent.com/trustsoc/community-rules/main/windows/fp_windows_update.yaml",
        "https://raw.githubusercontent.com/trustsoc/community-rules/main/linux/fp_cron_jobs.yaml",
    ]
    print(f"Syncing {len(urls)} suppression rule(s)...")
    for url in urls:
        try:
            result = _post(session, "/api/v1/suppressions/import-url", {"url": url})
            print(f"  ✓ {result['rule_name']} (id={str(result['id'])[:8]}...)")
        except requests.HTTPError as exc:
            print(f"  ✗ {url} — HTTP {exc.response.status_code}: {exc.response.text[:100]}")
        except Exception as exc:
            print(f"  ✗ {url} — {exc}")


def cmd_export(session, args):
    resource_type = getattr(args, "type", "alert")
    resource_id = args.id

    if resource_type == "case":
        path = f"/api/v1/cases/{resource_id}/export"
    else:
        path = f"/api/v1/alerts/{resource_id}/evidence"

    resp = session.get(f"{session.base_url}{path}")
    resp.raise_for_status()
    data = resp.json()

    output_file = getattr(args, "output", None) or f"{resource_type}_{resource_id[:8]}_export.json"
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"Exported to {output_file}")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def main():
    base_url = os.environ.get("TRUSTSOC_URL", "http://localhost:8000")
    api_key = os.environ.get("TRUSTSOC_KEY", "trustsoc_demo_key")

    parser = argparse.ArgumentParser(
        prog="trustsoc",
        description="TrustSOC CLI — interact with your SOC from the terminal",
    )
    parser.add_argument("--url", default=base_url, help="TrustSOC API base URL")
    parser.add_argument("--key", default=api_key, help="API key")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Health check + stats summary")
    sub.add_parser("plugins", help="List loaded enrichment plugins")

    demo_p = sub.add_parser("demo", help="Seed demo alerts")
    demo_p.add_argument("--count", type=int, default=8, help="Number of scenarios to seed (1-8)")

    sync_p = sub.add_parser("sync-rules", help="Import community suppression rules")
    sync_p.add_argument("urls", nargs="*", help="YAML rule URLs (defaults to community hub)")

    export_p = sub.add_parser("export", help="Export alert evidence or case bundle")
    export_p.add_argument("id", help="Alert or case UUID")
    export_p.add_argument("--type", choices=["alert", "case"], default="alert")
    export_p.add_argument("--output", help="Output filename")

    args = parser.parse_args()
    session = _client(args.url, args.key)

    commands = {
        "status": cmd_status,
        "plugins": cmd_plugins,
        "demo": cmd_demo,
        "sync-rules": cmd_sync_rules,
        "export": cmd_export,
    }

    try:
        commands[args.command](session, args)
    except requests.HTTPError as exc:
        print(f"API error {exc.response.status_code}: {exc.response.text[:200]}")
        sys.exit(1)
    except requests.ConnectionError:
        print(f"Cannot connect to {args.url}. Is TrustSOC running?")
        sys.exit(1)


if __name__ == "__main__":
    main()
