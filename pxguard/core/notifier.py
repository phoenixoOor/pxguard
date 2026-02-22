"""
PXGuard - Incident notification engine.

IncidentNotifier: SMTP health check, professional HTML email with embedded graph,
multipart/alternative (plain text fallback), cooldown-aware sending.
Credentials from env vars only; no password logging.
"""

import logging
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_GRAPH_CID = "pxguard_graph"


def _severity_badge(severity: str) -> tuple[str, str, str]:
    """Return (label, bg_color, text_color) for the severity badge."""
    s = severity.upper()
    if s == "CRITICAL":
        return "CRITICAL", "#f85149", "#ffffff"
    if s == "WARNING":
        return "WARNING", "#d29922", "#ffffff"
    return "OK", "#3fb950", "#ffffff"


def _build_html(
    *,
    severity: str,
    created: int,
    modified: int,
    deleted: int,
    total: int,
    threshold: int,
    timestamp_str: str,
    anomaly_state: str,
    total_scans: int,
    peak_changes: int,
    has_graph: bool,
) -> str:
    badge_label, badge_bg, badge_fg = _severity_badge(severity)

    graph_block = ""
    if has_graph:
        graph_block = (
            '<tr><td colspan="2" style="padding:16px 0;text-align:center;">'
            '<img src="cid:{cid}" alt="Activity Graph" '
            'style="max-width:100%%;border-radius:6px;border:1px solid #30363d;" />'
            "</td></tr>"
        ).format(cid=_GRAPH_CID)

    return """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<style>
  body {{ margin:0; padding:0; background:#0d1117; color:#c9d1d9;
         font-family:'Segoe UI',Roboto,Arial,sans-serif; }}
  .wrap {{ max-width:620px; margin:24px auto; padding:0 12px; }}
  .header {{ background:#161b22; border:1px solid #30363d; border-radius:10px 10px 0 0;
             padding:20px; text-align:center; }}
  .header h1 {{ margin:0 0 8px 0; font-size:22px; color:#58a6ff; }}
  .badge {{ display:inline-block; padding:5px 14px; border-radius:14px;
            font-weight:700; font-size:13px; letter-spacing:.5px;
            background:{badge_bg}; color:{badge_fg}; }}
  .body {{ background:#161b22; border:1px solid #30363d; border-top:none;
           border-radius:0 0 10px 10px; padding:20px; }}
  table {{ width:100%; border-collapse:collapse; margin:12px 0; }}
  td {{ padding:8px 12px; border-bottom:1px solid #21262d; font-size:14px; }}
  td:first-child {{ color:#8b949e; width:45%; }}
  td:last-child  {{ color:#c9d1d9; font-weight:600; }}
  .info {{ color:#8b949e; font-size:13px; line-height:1.6; margin:14px 0 0 0; }}
  .footer {{ text-align:center; color:#484f58; font-size:11px;
             margin:16px 0 0 0; padding:12px 0; }}
</style></head>
<body><div class="wrap">
  <div class="header">
    <h1>&#x1f6e1; PXGuard Security Alert</h1>
    <span class="badge">{badge_label}</span>
  </div>
  <div class="body">
    <table>
      <tr><td>Threat Level</td><td>{severity}</td></tr>
      <tr><td>Anomaly State</td><td>{anomaly_state}</td></tr>
      <tr><td>Created</td><td>{created}</td></tr>
      <tr><td>Modified</td><td>{modified}</td></tr>
      <tr><td>Deleted</td><td>{deleted}</td></tr>
      <tr><td>Total Changes</td><td>{total}</td></tr>
      <tr><td>Threshold</td><td>{threshold}</td></tr>
      <tr><td>Total Scans</td><td>{total_scans}</td></tr>
      <tr><td>Peak Changes</td><td>{peak_changes}</td></tr>
      <tr><td>Timestamp</td><td>{timestamp_str}</td></tr>
      {graph_block}
    </table>
    <p class="info">
      PXGuard detected file activity that exceeded the configured threshold.<br>
      Review the attached report for full details and the activity graph above
      for a visual timeline of changes.
    </p>
  </div>
  <div class="footer">
    PXGuard &mdash; File Integrity Monitoring &bull; Automated Incident Report
  </div>
</div></body></html>""".format(
        badge_bg=badge_bg,
        badge_fg=badge_fg,
        badge_label=badge_label,
        severity=severity,
        anomaly_state=anomaly_state or "N/A",
        created=created,
        modified=modified,
        deleted=deleted,
        total=total,
        threshold=threshold,
        total_scans=total_scans,
        peak_changes=peak_changes,
        timestamp_str=timestamp_str,
        graph_block=graph_block,
    )


def _build_plain_text(
    *,
    severity: str,
    created: int,
    modified: int,
    deleted: int,
    total: int,
    threshold: int,
    timestamp_str: str,
    anomaly_state: str,
    total_scans: int,
    peak_changes: int,
    report_body: str,
) -> str:
    return (
        "[PXGuard ALERT] Threat Level: {severity}\n"
        "================================================\n"
        "Timestamp:     {timestamp_str}\n"
        "Anomaly State: {anomaly_state}\n"
        "Created:       {created}\n"
        "Modified:      {modified}\n"
        "Deleted:       {deleted}\n"
        "Total:         {total}\n"
        "Threshold:     {threshold}\n"
        "Total Scans:   {total_scans}\n"
        "Peak Changes:  {peak_changes}\n"
        "================================================\n\n"
        "{report_body}\n"
    ).format(
        severity=severity,
        timestamp_str=timestamp_str,
        anomaly_state=anomaly_state or "N/A",
        created=created,
        modified=modified,
        deleted=deleted,
        total=total,
        threshold=threshold,
        total_scans=total_scans,
        peak_changes=peak_changes,
        report_body=report_body,
    )


class IncidentNotifier:
    """
    Production-level email notifier.
    - Validates SMTP connectivity at startup (verify_smtp).
    - Sends multipart/alternative HTML + plain-text emails.
    - Embeds PNG graph inline (Content-ID) and attaches report .txt.
    - No password logging; credentials from config dict (originally from env vars).
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._email_to: Optional[str] = (config.get("email_to") or "").strip() or None
        self._smtp_host: Optional[str] = (config.get("smtp_host") or "").strip() or None
        self._smtp_port: int = max(1, min(65535, int(config.get("smtp_port", 587))))
        self._smtp_user: Optional[str] = (config.get("smtp_user") or "").strip() or None
        self._smtp_password: Optional[str] = config.get("smtp_password") or None
        self._attach_visuals: bool = bool(config.get("attach_visuals", True))
        self._last_send_time: float = 0.0

    @property
    def is_configured(self) -> bool:
        return bool(self._smtp_host and self._email_to and self._smtp_user and self._smtp_password)

    def verify_smtp(self) -> bool:
        """
        Attempt SMTP connect + STARTTLS + login.
        Logs [SMTP] Connected / [SMTP] Authenticated on success.
        Returns True on success, raises RuntimeError on failure.
        """
        if not self.is_configured:
            raise RuntimeError(
                "SMTP not fully configured. Check env vars: "
                "PXGUARD_SMTP_HOST, PXGUARD_SMTP_PORT, PXGUARD_SMTP_USER, PXGUARD_SMTP_PASSWORD"
            )
        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=15) as server:
                server.starttls()
                logger.info("[SMTP] Connected to %s:%d", self._smtp_host, self._smtp_port)
                server.login(self._smtp_user, self._smtp_password)
                logger.info("[SMTP] Authenticated as %s", self._smtp_user)
            return True
        except smtplib.SMTPAuthenticationError as e:
            raise RuntimeError(f"SMTP authentication failed: {e}") from e
        except smtplib.SMTPException as e:
            raise RuntimeError(f"SMTP connection error: {e}") from e
        except Exception as e:
            raise RuntimeError(f"SMTP health check failed: {e}") from e

    def send_incident(
        self,
        *,
        report_path: Path,
        chart_path: Optional[Path] = None,
        severity: str = "CRITICAL",
        created: int = 0,
        modified: int = 0,
        deleted: int = 0,
        total: int = 0,
        threshold: int = 0,
        timestamp_str: str = "",
        anomaly_state: str = "",
        total_scans: int = 0,
        peak_changes: int = 0,
    ) -> bool:
        """
        Build and send professional HTML incident email.
        Returns True on success, False on failure (logged, never crashes caller).
        """
        if not self.is_configured:
            logger.debug("Incident not sent: SMTP not configured")
            return False

        report_path = Path(report_path)
        if not report_path.is_file():
            logger.warning("Report file not found: %s", report_path)
            return False

        try:
            report_body = report_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Could not read report %s: %s", report_path, e)
            return False

        has_chart = (
            self._attach_visuals
            and chart_path is not None
            and Path(chart_path).is_file()
        )

        subject = f"[PXGuard ALERT] Threat Level: {severity}"

        root_msg = MIMEMultipart("mixed")
        root_msg["Subject"] = subject
        root_msg["From"] = self._smtp_user
        root_msg["To"] = self._email_to

        alt_part = MIMEMultipart("alternative")

        plain = _build_plain_text(
            severity=severity,
            created=created,
            modified=modified,
            deleted=deleted,
            total=total,
            threshold=threshold,
            timestamp_str=timestamp_str,
            anomaly_state=anomaly_state,
            total_scans=total_scans,
            peak_changes=peak_changes,
            report_body=report_body,
        )
        alt_part.attach(MIMEText(plain, "plain", "utf-8"))

        html_related = MIMEMultipart("related")
        html_body = _build_html(
            severity=severity,
            created=created,
            modified=modified,
            deleted=deleted,
            total=total,
            threshold=threshold,
            timestamp_str=timestamp_str,
            anomaly_state=anomaly_state,
            total_scans=total_scans,
            peak_changes=peak_changes,
            has_graph=has_chart,
        )
        html_related.attach(MIMEText(html_body, "html", "utf-8"))

        if has_chart:
            try:
                img_data = Path(chart_path).read_bytes()
                img_part = MIMEImage(img_data, _subtype="png")
                img_part.add_header("Content-ID", f"<{_GRAPH_CID}>")
                img_part.add_header("Content-Disposition", "inline", filename=Path(chart_path).name)
                html_related.attach(img_part)
            except OSError as e:
                logger.warning("Could not embed chart %s: %s", chart_path, e)

        alt_part.attach(html_related)
        root_msg.attach(alt_part)

        if report_path.is_file():
            try:
                report_data = report_path.read_bytes()
                txt_part = MIMEBase("text", "plain")
                txt_part.set_payload(report_data)
                encoders.encode_base64(txt_part)
                txt_part.add_header("Content-Disposition", "attachment", filename=report_path.name)
                root_msg.attach(txt_part)
            except OSError as e:
                logger.warning("Could not attach report %s: %s", report_path, e)

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=30) as server:
                server.starttls()
                server.login(self._smtp_user, self._smtp_password)
                server.sendmail(self._smtp_user, self._email_to, root_msg.as_string())
            self._last_send_time = time.monotonic()
            logger.info("[EMAIL] Alert email sent successfully to %s", self._email_to)
            return True
        except smtplib.SMTPException as e:
            logger.warning("[EMAIL] SMTP error: %s", e)
            return False
        except Exception as e:
            logger.warning("[EMAIL] Failed to send: %s", e, exc_info=True)
            return False
