# Wazuh → TrustSOC Integration

Connect your Wazuh SIEM to TrustSOC in 10 minutes. Wazuh will forward every alert to TrustSOC for enrichment, correlation, and automated response.

## What you get

- Every Wazuh alert enriched with VirusTotal + AbuseIPDB + OTX threat intel
- Brute-force, lateral movement, and privilege escalation auto-correlated into incidents
- MITRE ATT&CK technique mapping for every incident
- Slack notification when a high-risk incident fires
- Cryptographic evidence trail for every decision (compliance-ready)
- LLM-generated investigation narratives

## Prerequisites

- Wazuh Manager 4.x or later
- TrustSOC running and reachable (Render free tier works)
- Your TrustSOC API key

---

## Step 1 — Add the integration to ossec.conf

Edit `/var/ossec/etc/ossec.conf` on your Wazuh Manager and add inside `<ossec_config>`:

```xml
<integration>
  <name>custom-trustsoc</name>
  <hook_url>https://YOUR_TRUSTSOC_URL/api/v1/alerts</hook_url>
  <api_key>YOUR_TRUSTSOC_API_KEY</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Replace `YOUR_TRUSTSOC_URL` and `YOUR_TRUSTSOC_API_KEY` with your values.

The `<level>7</level>` means only alerts at Wazuh level 7 or higher are forwarded (reduces noise). Adjust to taste — level 5 for more alerts, level 10 for less.

Copy the ready-made snippet:
```bash
# The snippet is already filled with placeholders:
cat wazuh_integration/ossec_snippet.xml
```

---

## Step 2 — Create the custom integration script

Wazuh's `custom-trustsoc` integration needs a script to transform its JSON and POST to TrustSOC.

```bash
sudo tee /var/ossec/integrations/custom-trustsoc << 'EOF'
#!/usr/bin/env python3
import sys
import json
import os
import urllib.request
import urllib.error

# Read from Wazuh
alert_file = open(sys.argv[1])
hook_url   = sys.argv[3]        # <hook_url> value
api_key    = sys.argv[2]        # <api_key> value

alert_json = json.load(alert_file)
alert_file.close()

payload = json.dumps({
    "source_system": "wazuh",
    "external_id": alert_json.get("id", ""),
    "alert_data": alert_json,
}).encode("utf-8")

req = urllib.request.Request(
    hook_url,
    data=payload,
    headers={
        "Content-Type": "application/json",
        "x-api-key": api_key,
    },
    method="POST",
)
try:
    urllib.request.urlopen(req, timeout=10)
except urllib.error.URLError as e:
    print(f"TrustSOC integration error: {e}", file=sys.stderr)
    sys.exit(1)
EOF

sudo chmod 750 /var/ossec/integrations/custom-trustsoc
sudo chown root:ossec /var/ossec/integrations/custom-trustsoc
```

---

## Step 3 — Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
# or on older installs:
sudo /var/ossec/bin/ossec-control restart
```

---

## Step 4 — Verify

Watch the integration log:
```bash
sudo tail -f /var/ossec/logs/integrations.log
```

You should see lines like:
```
2025-01-15 10:23:44 INFO: Sending alert to custom-trustsoc
```

Then check TrustSOC received it:
```bash
curl -H "x-api-key: YOUR_API_KEY" https://YOUR_TRUSTSOC_URL/api/v1/alerts
```

---

## Optional: Active Response (IP blocking)

To have TrustSOC actually block malicious IPs via Wazuh's firewall-drop mechanism:

### Install the response script
```bash
sudo cp wazuh_integration/wazuh_active_response.sh /var/ossec/active-response/bin/trustsoc-block
sudo chmod 750 /var/ossec/active-response/bin/trustsoc-block
sudo chown root:ossec /var/ossec/active-response/bin/trustsoc-block
```

### Set env vars for the script
```bash
sudo tee /etc/default/wazuh-trustsoc << EOF
TRUSTSOC_URL=https://YOUR_TRUSTSOC_URL
TRUSTSOC_KEY=YOUR_TRUSTSOC_API_KEY
EOF
```

### Add to ossec.conf
```xml
<command>
  <name>trustsoc-block</name>
  <executable>trustsoc-block</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>trustsoc-block</command>
  <location>server</location>
  <rules_id>5763,100002,100050</rules_id>
  <timeout>900</timeout>
</active-response>
```

TrustSOC will run its guardrails before executing: never blocks private IPs, never blocks critical assets, respects the hourly rate limit.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| No alerts arriving in TrustSOC | Check `/var/ossec/logs/integrations.log` for errors |
| 401 Unauthorized | Verify `<api_key>` matches `API_KEY` in TrustSOC `.env` |
| Alerts arriving but all risk_score=25 | Set `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` in TrustSOC env |
| Wazuh restart fails | Check ossec.conf syntax with `sudo /var/ossec/bin/ossec-logtest` |
