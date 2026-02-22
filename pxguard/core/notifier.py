"""
PXGuard - Incident notifier (orchestrator).

Thin orchestrator that wires together:
  - ReportBuilder  (template rendering)
  - EmailService   (SMTP transport)

No inline HTML. No SMTP logic. Pure coordination.
"""

import logging
from pathlib import Path
from typing import Any, Optional

from pxguard.core.email_service import EmailService, SMTPConfig
from pxguard.core.report_builder import GRAPH_CID, IncidentContext, ReportBuilder

logger = logging.getLogger(__name__)


class IncidentNotifier:
    """
    Orchestrates incident email delivery.
    Injected with EmailService and ReportBuilder at construction time.
    """

    def __init__(
        self,
        config: dict[str, Any],
        email_service: Optional[EmailService] = None,
        report_builder: Optional[ReportBuilder] = None,
    ) -> None:
        smtp_cfg = SMTPConfig(
            host=(config.get("smtp_host") or "").strip(),
            port=max(1, min(65535, int(config.get("smtp_port", 587)))),
            user=(config.get("smtp_user") or "").strip(),
            password=config.get("smtp_password") or "",
            email_to=(config.get("email_to") or "").strip(),
        )
        self._email_service = email_service or EmailService(smtp_cfg)
        self._report_builder = report_builder or ReportBuilder()
        self._attach_visuals = bool(config.get("attach_visuals", True))

    @property
    def is_configured(self) -> bool:
        return self._email_service.is_configured

    def verify_smtp(self) -> None:
        """Delegate SMTP health check to EmailService. Raises RuntimeError on failure."""
        self._email_service.verify()

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
        cooldown_seconds: int = 300,
        timestamp_str: str = "",
        anomaly_state: str = "",
        total_scans: int = 0,
        peak_changes: int = 0,
        changed_files: Optional[list[dict]] = None,
    ) -> bool:
        """
        Build and send incident email.
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

        ctx = IncidentContext(
            severity=severity,
            anomaly_state=anomaly_state or "N/A",
            created=created,
            modified=modified,
            deleted=deleted,
            total=total,
            threshold=threshold,
            cooldown_seconds=cooldown_seconds,
            total_scans=total_scans,
            peak_changes=peak_changes,
            timestamp_str=timestamp_str,
            has_graph=has_chart,
            changed_files=changed_files or [],
            report_body=report_body,
        )

        try:
            html = self._report_builder.render_html(ctx)
            plain = self._report_builder.render_plain_text(ctx)
            logger.debug("[EMAIL] Report rendered successfully")
        except Exception as e:
            logger.warning("[EMAIL] Template rendering failed: %s", e)
            return False

        try:
            msg = self._email_service.build_message(
                subject=ctx.subject,
                plain_text=plain,
                html_body=html,
                graph_path=Path(chart_path) if has_chart else None,
                graph_cid=GRAPH_CID,
                report_path=report_path,
            )
            logger.debug("[EMAIL] MIME message built successfully")
        except Exception as e:
            logger.warning("[EMAIL] Message build failed: %s", e)
            return False

        return self._email_service.send(msg)
