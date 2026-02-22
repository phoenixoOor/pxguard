"""
PXGuard - Report builder.

Renders email HTML from Jinja2 template and builds plain-text fallback.
Pure data-in / string-out — no SMTP, no MIME, no side effects.
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

logger = logging.getLogger(__name__)

GRAPH_CID = "pxguard_graph"
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


@dataclass
class IncidentContext:
    """All data needed to render an incident report email."""

    severity: str = "CRITICAL"
    anomaly_state: str = "N/A"
    created: int = 0
    modified: int = 0
    deleted: int = 0
    total: int = 0
    threshold: int = 0
    cooldown_seconds: int = 300
    total_scans: int = 0
    peak_changes: int = 0
    timestamp_str: str = ""
    has_graph: bool = False
    changed_files: list[dict] = field(default_factory=list)
    reaction_actions: list[dict] = field(default_factory=list)
    report_body: str = ""

    @property
    def generated_at(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    @property
    def subject(self) -> str:
        return f"[PXGuard ALERT] Threat Level: {self.severity}"


class ReportBuilder:
    """
    Renders incident reports from Jinja2 templates.
    Templates are loaded from pxguard/templates/ on first use and cached.
    """

    def __init__(self, templates_dir: Optional[Path] = None) -> None:
        tpl_dir = templates_dir or _TEMPLATES_DIR
        if not tpl_dir.is_dir():
            raise FileNotFoundError(f"Templates directory not found: {tpl_dir}")
        self._env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=True,
        )
        logger.debug("[REPORT] Template directory: %s", tpl_dir)

    def render_html(self, ctx: IncidentContext) -> str:
        """Render email_report.html with the given context. Raises on missing template."""
        try:
            template = self._env.get_template("email_report.html")
        except TemplateNotFound as e:
            raise FileNotFoundError(f"Email template not found: {e}") from e
        html = template.render(
            severity=ctx.severity,
            anomaly_state=ctx.anomaly_state or "N/A",
            created=ctx.created,
            modified=ctx.modified,
            deleted=ctx.deleted,
            total=ctx.total,
            threshold=ctx.threshold,
            cooldown_seconds=ctx.cooldown_seconds,
            total_scans=ctx.total_scans,
            peak_changes=ctx.peak_changes,
            timestamp_str=ctx.timestamp_str,
            has_graph=ctx.has_graph,
            graph_cid=GRAPH_CID,
            changed_files=ctx.changed_files,
            reaction_actions=ctx.reaction_actions,
            generated_at=ctx.generated_at,
        )
        logger.debug("[REPORT] HTML email rendered (%d chars)", len(html))
        return html

    def render_plain_text(self, ctx: IncidentContext) -> str:
        """Build plain-text fallback for email clients that don't support HTML."""
        lines = [
            f"[PXGuard ALERT] Threat Level: {ctx.severity}",
            "=" * 52,
            f"Timestamp:     {ctx.timestamp_str}",
            f"Anomaly State: {ctx.anomaly_state or 'N/A'}",
            f"Created:       {ctx.created}",
            f"Modified:      {ctx.modified}",
            f"Deleted:       {ctx.deleted}",
            f"Total:         {ctx.total}",
            f"Threshold:     {ctx.threshold}",
            f"Cooldown:      {ctx.cooldown_seconds}s",
            f"Total Scans:   {ctx.total_scans}",
            f"Peak Changes:  {ctx.peak_changes}",
            "=" * 52,
        ]
        if ctx.changed_files:
            lines.append("")
            lines.append(f"Changed Files ({len(ctx.changed_files)}):")
            for f in ctx.changed_files[:50]:
                lines.append(f"  {f.get('event', '?'):10s} {f.get('path', '?')}")
            if len(ctx.changed_files) > 50:
                lines.append(f"  ... and {len(ctx.changed_files) - 50} more")
        if ctx.reaction_actions:
            lines.append("")
            lines.append(f"Automated Actions ({len(ctx.reaction_actions)}):")
            for a in ctx.reaction_actions:
                status = "OK" if a.get("success") else "FAILED"
                lines.append(
                    "  %s pid=%s name=%s file=%s — %s"
                    % (a.get("action", "?"), a.get("pid", "?"), a.get("process_name", "?"), a.get("file_path", "?"), status)
                )
        if ctx.report_body:
            lines.append("")
            lines.append(ctx.report_body)
        lines.append("")
        lines.append(f"Generated: {ctx.generated_at}")
        return "\n".join(lines) + "\n"
