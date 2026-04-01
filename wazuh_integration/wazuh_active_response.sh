#!/bin/bash
# TrustSOC — Wazuh Active Response Script
# =========================================
# Blocks a source IP by calling TrustSOC's action executor,
# which runs guardrails before executing.
#
# Install:
#   sudo cp wazuh_active_response.sh /var/ossec/active-response/bin/trustsoc-block
#   sudo chmod 750 /var/ossec/active-response/bin/trustsoc-block
#   sudo chown root:ossec /var/ossec/active-response/bin/trustsoc-block
#
# Add to ossec.conf (inside <ossec_config>):
#   <active-response>
#     <command>trustsoc-block</command>
#     <location>server</location>
#     <rules_id>5763,100002</rules_id>      <!-- adjust rule IDs as needed -->
#     <timeout>900</timeout>                 <!-- 15 min auto-unblock -->
#   </active-response>
#
#   <command>
#     <name>trustsoc-block</name>
#     <executable>trustsoc-block</executable>
#     <expect>srcip</expect>
#     <timeout_allowed>yes</timeout_allowed>
#   </command>

TRUSTSOC_URL="${TRUSTSOC_URL:-https://YOUR_TRUSTSOC_URL}"
TRUSTSOC_KEY="${TRUSTSOC_KEY:-YOUR_TRUSTSOC_API_KEY}"

LOCAL=$(dirname "$0")
cd "$LOCAL/../tmp" || exit 1

# Read Wazuh active-response input from stdin
read -r INPUT
ACTION=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))")
SRCIP=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('parameters',{}).get('srcip',''))")
ALERT_ID=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('parameters',{}).get('alert',{}).get('id',''))")

if [ -z "$SRCIP" ]; then
  echo "trustsoc-block: no srcip found, skipping" >> /var/ossec/logs/active-responses.log
  exit 0
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [ "$ACTION" = "add" ]; then
  # Notify TrustSOC to execute block (runs guardrails internally)
  curl -s -X POST \
    "${TRUSTSOC_URL}/api/v1/actions/execute" \
    -H "x-api-key: ${TRUSTSOC_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"action_type\": \"block_ip\", \"target_ip\": \"${SRCIP}\", \"source\": \"wazuh_active_response\", \"wazuh_alert_id\": \"${ALERT_ID}\"}" \
    >> /var/ossec/logs/active-responses.log 2>&1

  echo "${TIMESTAMP} trustsoc-block: block requested for ${SRCIP}" >> /var/ossec/logs/active-responses.log
else
  # Unblock request
  curl -s -X POST \
    "${TRUSTSOC_URL}/api/v1/actions/unblock" \
    -H "x-api-key: ${TRUSTSOC_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"action_type\": \"unblock_ip\", \"target_ip\": \"${SRCIP}\"}" \
    >> /var/ossec/logs/active-responses.log 2>&1

  echo "${TIMESTAMP} trustsoc-block: unblock requested for ${SRCIP}" >> /var/ossec/logs/active-responses.log
fi

exit 0
