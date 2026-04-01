"""
Email digest notifications via Gmail SMTP (or any SMTP server).

Sends a formatted HTML daily digest summarising:
  - Alert counts (24h)
  - New incidents
  - Top MITRE techniques
  - High-risk open alerts

Config (all optional — email is skipped if SMTP_USER is not set):
  SMTP_HOST      — SMTP server host (default: smtp.gmail.com)
  SMTP_PORT      — SMTP port (default: 587, TLS)
  SMTP_USER      — Gmail address (e.g. alerts@yourdomain.com)
  SMTP_PASSWORD  — Gmail App Password (not your account password)
                   https://myaccount.google.com/apppasswords
  DIGEST_EMAIL_TO — Recipient address (comma-separated for multiple)

Gmail free tier: 500 emails/day.
"""

import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

from app.config import settings

log = logging.getLogger(__name__)


def _smtp_enabled() -> bool:
    return bool(
        getattr(settings, "SMTP_USER", None)
        and getattr(settings, "SMTP_PASSWORD", None)
        and getattr(settings, "DIGEST_EMAIL_TO", None)
    )


def _send(subject: str, html_body: str, text_body: str) -> None:
    if not _smtp_enabled():
        log.debug("Email notifications disabled (SMTP_USER not configured)")
        return

    smtp_host = getattr(settings, "SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(getattr(settings, "SMTP_PORT", "587"))
    from_addr = settings.SMTP_USER
    to_addrs  = [a.strip() for a in settings.DIGEST_EMAIL_TO.split(",")]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"TrustSOC Alerts <{from_addr}>"
    msg["To"]      = ", ".join(to_addrs)

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(from_addr, to_addrs, msg.as_string())
        log.info("Email digest sent to %s", to_addrs)
    except Exception as exc:
        log.warning("Email send failed: %s", exc)


def send_digest(
    alert_count_24h: int,
    incident_count_24h: int,
    high_risk_open: int,
    top_techniques: List[dict],
    recent_high_risk: List[dict],
) -> None:
    """
    Send a formatted HTML digest email.

    Args:
        alert_count_24h:    Total alerts in last 24h
        incident_count_24h: New incidents in last 24h
        high_risk_open:     High-risk alerts currently open
        top_techniques:     List of {"technique": "T1110", "count": 5}
        recent_high_risk:   List of {"title": "...", "score": 87, "host": "..."}
    """
    now = datetime.now(timezone.utc)
    subject = f"TrustSOC Daily Digest — {now.strftime('%Y-%m-%d')} | {alert_count_24h} alerts, {incident_count_24h} incidents"

    techniques_rows = "".join(
        f"<tr><td>{t['technique']}</td><td>{t.get('count', 0)}</td></tr>"
        for t in top_techniques[:10]
    ) or "<tr><td colspan='2'>No techniques detected</td></tr>"

    alerts_rows = "".join(
        f"<tr><td>{a.get('title','—')[:60]}</td><td>{a.get('score',0)}</td><td>{a.get('host','—')}</td></tr>"
        for a in recent_high_risk[:10]
    ) or "<tr><td colspan='3'>No high-risk alerts</td></tr>"

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
<style>
  body {{ font-family: Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  .container {{ max-width: 700px; margin: 0 auto; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  h2 {{ color: #79c0ff; margin-top: 24px; }}
  .stat-row {{ display: flex; gap: 16px; margin: 16px 0; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px;
           padding: 12px 20px; text-align: center; flex: 1; }}
  .stat .number {{ font-size: 2em; font-weight: bold; color: #58a6ff; }}
  .stat .label {{ font-size: 0.8em; color: #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th {{ background: #161b22; color: #8b949e; text-align: left; padding: 8px; font-size: 0.85em; }}
  td {{ padding: 8px; border-bottom: 1px solid #21262d; font-size: 0.9em; }}
  .footer {{ margin-top: 32px; font-size: 0.75em; color: #484f58; border-top: 1px solid #30363d; padding-top: 12px; }}
</style>
</head>
<body>
<div class="container">
  <h1>TrustSOC Daily Digest</h1>
  <p style="color:#8b949e">{now.strftime("%A, %B %d %Y — %H:%M UTC")}</p>

  <div class="stat-row">
    <div class="stat"><div class="number">{alert_count_24h}</div><div class="label">Alerts (24h)</div></div>
    <div class="stat"><div class="number">{incident_count_24h}</div><div class="label">Incidents (24h)</div></div>
    <div class="stat"><div class="number" style="color:#f85149">{high_risk_open}</div><div class="label">High-Risk Open</div></div>
  </div>

  <h2>Top MITRE ATT&CK Techniques</h2>
  <table>
    <tr><th>Technique</th><th>Incidents</th></tr>
    {techniques_rows}
  </table>

  <h2>Recent High-Risk Alerts</h2>
  <table>
    <tr><th>Title</th><th>Risk Score</th><th>Host</th></tr>
    {alerts_rows}
  </table>

  <div class="footer">
    Generated by TrustSOC &mdash; open-source SOC automation<br>
    To stop receiving these emails, unset DIGEST_EMAIL_TO in your environment.
  </div>
</div>
</body>
</html>
"""

    text_body = (
        f"TrustSOC Daily Digest — {now.strftime('%Y-%m-%d')}\n"
        f"{'='*50}\n"
        f"Alerts (24h):      {alert_count_24h}\n"
        f"Incidents (24h):   {incident_count_24h}\n"
        f"High-Risk Open:    {high_risk_open}\n\n"
        "Top MITRE Techniques:\n"
        + "\n".join(f"  {t['technique']}: {t.get('count',0)}" for t in top_techniques[:10])
        + "\n\nRecent High-Risk Alerts:\n"
        + "\n".join(f"  [{a.get('score',0)}] {a.get('title','—')} — {a.get('host','—')}" for a in recent_high_risk[:10])
    )

    _send(subject, html_body, text_body)
