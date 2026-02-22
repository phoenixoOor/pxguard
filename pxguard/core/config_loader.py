"""
PXGuard - Configuration loader.

Loads and validates config.yaml; resolves paths relative to project root.
SMTP credentials are loaded ONLY from environment variables (never from YAML).
"""

import logging
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SMTP_ENV_VARS = {
    "PXGUARD_SMTP_HOST": "SMTP server hostname (e.g. smtp.gmail.com)",
    "PXGUARD_SMTP_PORT": "SMTP server port (e.g. 587)",
    "PXGUARD_SMTP_USER": "SMTP login username / sender address",
    "PXGUARD_SMTP_PASSWORD": "SMTP password or app-password",
}


def _validate_email_env(email_alerts_enabled: bool) -> dict[str, Any]:
    """
    When email_alerts_enabled is True, read and validate SMTP env vars.
    Raises RuntimeError if any required variable is missing.
    Returns dict with smtp_host, smtp_port, smtp_user, smtp_password.
    """
    if not email_alerts_enabled:
        return {
            "smtp_host": None,
            "smtp_port": 587,
            "smtp_user": None,
            "smtp_password": None,
        }
    missing = [name for name in _SMTP_ENV_VARS if not os.environ.get(name, "").strip()]
    if missing:
        lines = ["Email alerts are enabled but required environment variables are missing:"]
        for name in missing:
            lines.append(f"  {name}  — {_SMTP_ENV_VARS[name]}")
        lines.append("")
        lines.append("Set them in your shell or in a .env file, then restart PXGuard.")
        raise RuntimeError("\n".join(lines))
    return {
        "smtp_host": os.environ["PXGUARD_SMTP_HOST"].strip(),
        "smtp_port": max(1, min(65535, int(os.environ.get("PXGUARD_SMTP_PORT", "587")))),
        "smtp_user": os.environ["PXGUARD_SMTP_USER"].strip(),
        "smtp_password": os.environ["PXGUARD_SMTP_PASSWORD"],
    }


def load_config(config_path: Path, project_root: Optional[Path] = None) -> dict[str, Any]:
    """
    Load YAML config and resolve paths relative to project_root.

    Args:
        config_path: Path to config.yaml.
        project_root: Base for relative paths; defaults to config_path parent's parent.

    Returns:
        Config dict with resolved paths and defaults applied.
    """
    try:
        import yaml
    except ImportError:
        logger.error("PyYAML is required. Install with: pip install pyyaml")
        raise

    path = config_path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Config not found: {path}")

    root = project_root or path.parent.parent
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    monitoring = raw.get("monitoring", {})
    directories = monitoring.get("directories", ["./baseline", "./test_assets"])
    scan_interval = int(monitoring.get("scan_interval", 30))
    exclude_patterns = list(monitoring.get("exclude_patterns", []))
    watchdog_enabled = bool(monitoring.get("watchdog_enabled", False))
    watchdog_debounce_seconds = float(monitoring.get("watchdog_debounce_seconds", 2.0))

    thresholds_raw = raw.get("thresholds", {})
    change_count = int(thresholds_raw.get("change_count", 10))
    time_window_seconds = int(thresholds_raw.get("time_window_seconds", 60))
    cooldown_seconds = thresholds_raw.get("cooldown_seconds")
    if cooldown_seconds is None:
        cooldown_seconds = time_window_seconds
    else:
        cooldown_seconds = int(cooldown_seconds)
    anomaly_cooldown_seconds = float(thresholds_raw.get("anomaly_cooldown_seconds", 300.0))

    dashboard_raw = raw.get("dashboard", {})
    dashboard_interactive = bool(dashboard_raw.get("interactive", True))
    dashboard_history_size = int(dashboard_raw.get("history_size", 60))

    alerts_raw = raw.get("alerts", {})
    log_path = alerts_raw.get("log_path", "./logs/alerts.log")
    console_alerts = bool(alerts_raw.get("console_alerts", True))
    min_severity = str(alerts_raw.get("min_severity", "INFO")).upper()
    email_alerts_enabled = bool(alerts_raw.get("email_alerts_enabled", False))
    email_to = str(alerts_raw.get("email_to", "")).strip() or None
    attach_visuals = bool(alerts_raw.get("attach_visuals", True))

    smtp = _validate_email_env(email_alerts_enabled)

    paths_raw = raw.get("paths", {})
    baseline_file = paths_raw.get("baseline_file", "./baseline/baseline.json")
    graph_format = str(paths_raw.get("graph_format", "html")).lower()
    if graph_format not in ("html", "png"):
        graph_format = "html"

    reaction_raw = raw.get("reaction", {})
    reaction_enabled = bool(reaction_raw.get("enabled", False))

    simulator_raw = raw.get("simulator", {})
    allowed_root = simulator_raw.get("allowed_root", "./test_assets")

    def resolve(p: str) -> Path:
        path_obj = Path(p)
        return (root / path_obj).resolve() if not path_obj.is_absolute() else path_obj.resolve()

    log_dir = resolve(log_path).parent
    report_summary_path = log_dir / "report_summary.txt"

    return {
        "project_root": root,
        "directories": [resolve(d) for d in directories],
        "dashboard_interactive": dashboard_interactive,
        "dashboard_history_size": max(10, min(100, dashboard_history_size)),
        "scan_interval": scan_interval,
        "exclude_patterns": exclude_patterns,
        "watchdog_enabled": watchdog_enabled,
        "watchdog_debounce_seconds": max(0.5, watchdog_debounce_seconds),
        "threshold_change_count": change_count,
        "threshold_time_window_seconds": time_window_seconds,
        "threshold_cooldown_seconds": cooldown_seconds,
        "anomaly_cooldown_seconds": max(60.0, anomaly_cooldown_seconds),
        "alert_log_path": resolve(log_path),
        "console_alerts": console_alerts,
        "min_severity": min_severity,
        "email_alerts_enabled": email_alerts_enabled,
        "email_to": email_to,
        "smtp_host": smtp["smtp_host"],
        "smtp_port": smtp["smtp_port"],
        "smtp_user": smtp["smtp_user"],
        "smtp_password": smtp["smtp_password"],
        "attach_visuals": attach_visuals,
        "baseline_path": resolve(baseline_file),
        "simulator_allowed_root": resolve(allowed_root),
        "reaction_enabled": reaction_enabled,
        "graph_format": graph_format,
        "report_summary_path": report_summary_path,
    }
