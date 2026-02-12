"""
PXGuard - Configuration loader.

Loads and validates config.yaml; resolves paths relative to project root.
"""

import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


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

    thresholds_raw = raw.get("thresholds", {})
    change_count = int(thresholds_raw.get("change_count", 10))
    time_window_seconds = int(thresholds_raw.get("time_window_seconds", 60))

    alerts_raw = raw.get("alerts", {})
    log_path = alerts_raw.get("log_path", "./logs/alerts.log")
    console_alerts = bool(alerts_raw.get("console_alerts", True))
    min_severity = str(alerts_raw.get("min_severity", "INFO")).upper()

    paths_raw = raw.get("paths", {})
    baseline_file = paths_raw.get("baseline_file", "./baseline/baseline.json")

    simulator_raw = raw.get("simulator", {})
    allowed_root = simulator_raw.get("allowed_root", "./test_assets")

    def resolve(p: str) -> Path:
        path_obj = Path(p)
        return (root / path_obj).resolve() if not path_obj.is_absolute() else path_obj.resolve()

    return {
        "project_root": root,
        "directories": [resolve(d) for d in directories],
        "scan_interval": scan_interval,
        "exclude_patterns": exclude_patterns,
        "threshold_change_count": change_count,
        "threshold_time_window_seconds": time_window_seconds,
        "alert_log_path": resolve(log_path),
        "console_alerts": console_alerts,
        "min_severity": min_severity,
        "baseline_path": resolve(baseline_file),
        "simulator_allowed_root": resolve(allowed_root),
    }
