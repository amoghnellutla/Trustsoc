#!/usr/bin/env python3
"""
TrustSOC Syslog Forwarder
==========================
Listens on UDP/TCP syslog (port 514) and forwards parsed events to TrustSOC.
Supports CEF, RFC 5424, and plain syslog formats.

No external dependencies beyond stdlib + requests.

Usage:
    python3 syslog_forwarder.py

Environment vars:
    TRUSTSOC_URL     = https://your-trustsoc-url  (required)
    TRUSTSOC_KEY     = your-api-key               (required)
    SYSLOG_PORT      = 514                        (default)
    SYSLOG_PROTO     = udp                        (udp or tcp)
    MIN_SEVERITY     = warning                    (debug/info/notice/warning/error/critical)
    BATCH_SIZE       = 10                         (events to buffer before flushing)

Run as a service (systemd):
    sudo cp syslog_forwarder.py /usr/local/bin/trustsoc-forwarder
    sudo chmod +x /usr/local/bin/trustsoc-forwarder
    # then create /etc/systemd/system/trustsoc-forwarder.service (see README)
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import socketserver
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

TRUSTSOC_URL = os.getenv("TRUSTSOC_URL", "").rstrip("/")
TRUSTSOC_KEY = os.getenv("TRUSTSOC_KEY", "")
SYSLOG_PORT  = int(os.getenv("SYSLOG_PORT", "514"))
SYSLOG_PROTO = os.getenv("SYSLOG_PROTO", "udp").lower()
BATCH_SIZE   = int(os.getenv("BATCH_SIZE", "10"))
MIN_SEVERITY = os.getenv("MIN_SEVERITY", "warning").lower()

SEVERITY_ORDER = ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]
MIN_SEV_INDEX  = SEVERITY_ORDER.index(MIN_SEVERITY) if MIN_SEVERITY in SEVERITY_ORDER else 3

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("trustsoc-forwarder")

# Batch buffer + lock
_batch: List[Dict] = []
_batch_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Syslog parsing
# ---------------------------------------------------------------------------

# CEF: CEF:0|vendor|product|version|id|name|severity|...
_CEF_RE = re.compile(r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)", re.S)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_RFC5424_RE = re.compile(
    r"<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)", re.S
)

# BSD syslog: <PRI>MMM DD HH:MM:SS HOSTNAME MSG
_BSD_RE = re.compile(r"<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)", re.S)


def _sev_from_pri(pri: int) -> str:
    sev_code = pri & 0x7
    return ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"][sev_code]


def parse_syslog(raw: str) -> Optional[Dict[str, Any]]:
    raw = raw.strip()

    # Try CEF
    m = _CEF_RE.match(raw)
    if m:
        _, vendor, product, _, sig_id, name, severity_str, extensions = m.groups()
        ext = {}
        for kv in re.findall(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)", extensions):
            ext[kv[0]] = kv[1].strip()
        sev_map = {"0": "info", "1": "low", "2": "low", "3": "low",
                   "4": "medium", "5": "medium", "6": "medium",
                   "7": "high", "8": "high", "9": "critical", "10": "critical"}
        return {
            "source_system": "syslog",
            "format": "cef",
            "title": name,
            "severity": sev_map.get(severity_str.strip(), "medium"),
            "source_host": ext.get("dhost") or ext.get("shost") or "unknown",
            "source_ip": ext.get("src") or ext.get("dst"),
            "vendor": vendor,
            "product": product,
            "sig_id": sig_id,
            "extensions": ext,
            "raw": raw,
        }

    # Try RFC 5424
    m = _RFC5424_RE.match(raw)
    if m:
        pri_str, _, timestamp, hostname, app, _, _, _, msg = m.groups()
        pri = int(pri_str)
        sev = _sev_from_pri(pri)
        return {
            "source_system": "syslog",
            "format": "rfc5424",
            "title": f"{app}: {msg[:120]}",
            "severity": sev if sev in ("critical", "error", "warning") else "low",
            "source_host": hostname,
            "timestamp": timestamp,
            "app": app,
            "message": msg,
            "raw": raw,
        }

    # Try BSD syslog
    m = _BSD_RE.match(raw)
    if m:
        pri_str, timestamp, hostname, msg = m.groups()
        pri = int(pri_str)
        sev = _sev_from_pri(pri)
        return {
            "source_system": "syslog",
            "format": "bsd",
            "title": msg[:120],
            "severity": sev if sev in ("critical", "error", "warning") else "low",
            "source_host": hostname,
            "timestamp": timestamp,
            "message": msg,
            "raw": raw,
        }

    # Fallback: plain text
    return {
        "source_system": "syslog",
        "format": "plain",
        "title": raw[:120],
        "severity": "low",
        "source_host": "unknown",
        "message": raw,
        "raw": raw,
    }


def _should_forward(parsed: Dict) -> bool:
    sev = parsed.get("severity", "low").lower()
    # Map severity to index
    sev_map = {"low": 1, "info": 1, "notice": 2, "warning": 3, "medium": 3,
               "error": 4, "high": 4, "critical": 5, "emergency": 6, "alert": 6}
    return sev_map.get(sev, 0) >= MIN_SEV_INDEX


# ---------------------------------------------------------------------------
# TrustSOC sender
# ---------------------------------------------------------------------------

def _send_to_trustsoc(events: List[Dict]) -> None:
    if not TRUSTSOC_URL or not TRUSTSOC_KEY:
        log.warning("TRUSTSOC_URL or TRUSTSOC_KEY not set — dropping %d events", len(events))
        return

    headers = {"x-api-key": TRUSTSOC_KEY, "Content-Type": "application/json"}
    sent, failed = 0, 0

    for ev in events:
        payload = {
            "source_system": ev.get("source_system", "syslog"),
            "external_id": f"syslog-{uuid.uuid4().hex[:12]}",
            "alert_data": ev,
        }
        try:
            r = requests.post(
                f"{TRUSTSOC_URL}/api/v1/alerts",
                json=payload,
                headers=headers,
                timeout=8,
            )
            r.raise_for_status()
            sent += 1
        except Exception as exc:
            log.warning("Failed to send event: %s", exc)
            failed += 1

    log.info("Flushed batch: sent=%d failed=%d", sent, failed)


def _flush_batch() -> None:
    with _batch_lock:
        if not _batch:
            return
        to_send = _batch[:]
        _batch.clear()
    _send_to_trustsoc(to_send)


def _add_to_batch(parsed: Dict) -> None:
    with _batch_lock:
        _batch.append(parsed)
        should_flush = len(_batch) >= BATCH_SIZE
    if should_flush:
        threading.Thread(target=_flush_batch, daemon=True).start()


# ---------------------------------------------------------------------------
# Syslog server handlers
# ---------------------------------------------------------------------------

class UDPSyslogHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0].decode("utf-8", errors="replace")
        parsed = parse_syslog(data)
        if parsed and _should_forward(parsed):
            _add_to_batch(parsed)


class TCPSyslogHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        buf = b""
        while True:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            buf += chunk
        for line in buf.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                parsed = parse_syslog(line)
                if parsed and _should_forward(parsed):
                    _add_to_batch(parsed)


# ---------------------------------------------------------------------------
# Background flush timer (ensure events don't linger > 5s)
# ---------------------------------------------------------------------------

def _flush_timer() -> None:
    while True:
        time.sleep(5)
        _flush_batch()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not TRUSTSOC_URL:
        print("ERROR: Set TRUSTSOC_URL environment variable")
        print("  export TRUSTSOC_URL=https://your-trustsoc-url")
        sys.exit(1)
    if not TRUSTSOC_KEY:
        print("ERROR: Set TRUSTSOC_KEY environment variable")
        print("  export TRUSTSOC_KEY=your-api-key")
        sys.exit(1)

    # Verify connectivity
    try:
        r = requests.get(f"{TRUSTSOC_URL}/health", timeout=5)
        r.raise_for_status()
        log.info("TrustSOC reachable at %s", TRUSTSOC_URL)
    except Exception as exc:
        log.error("Cannot reach TrustSOC: %s", exc)
        sys.exit(1)

    # Start background flush timer
    t = threading.Thread(target=_flush_timer, daemon=True)
    t.start()

    # Start syslog listener
    if SYSLOG_PROTO == "tcp":
        server_cls = socketserver.TCPServer
        handler_cls = TCPSyslogHandler
    else:
        server_cls = socketserver.UDPServer
        handler_cls = UDPSyslogHandler

    log.info("Listening on %s port %d → forwarding to %s", SYSLOG_PROTO.upper(), SYSLOG_PORT, TRUSTSOC_URL)
    log.info("Min severity: %s | Batch size: %d", MIN_SEVERITY, BATCH_SIZE)

    with server_cls(("0.0.0.0", SYSLOG_PORT), handler_cls) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            log.info("Shutting down — flushing remaining events...")
            _flush_batch()


if __name__ == "__main__":
    main()
