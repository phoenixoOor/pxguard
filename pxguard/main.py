#!/usr/bin/env python3
"""
PXGuard - CLI entry point.

Exposed as the 'pxguard' console command via pyproject.toml.
"""

import argparse
import logging
import signal
import sys
from pathlib import Path


def setup_logging(verbose: bool = False) -> None:
    """Configure logging to stderr (no print-based logging)."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


def get_config(args: argparse.Namespace) -> dict:
    """Load config from file; config path may be overridden by args."""
    from pxguard.core.config_loader import load_config

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path
    config_path = config_path.resolve()
    project_root = Path.cwd().resolve()
    return load_config(config_path, project_root)


def cmd_init_baseline(config: dict, dry_run: bool) -> None:
    """Create or overwrite baseline from current directory state."""
    from pxguard.core.comparator import BaselineComparator
    from pxguard.core.scanner import DirectoryScanner

    logging.getLogger(__name__).info("Building baseline...")
    scanner = DirectoryScanner(exclude_patterns=config["exclude_patterns"])
    dirs = config["directories"]
    root = config["project_root"]
    manifest = scanner.scan_directories(dirs, root)
    baseline_path = Path(config["baseline_path"])
    if dry_run:
        logging.getLogger(__name__).info("Dry run: would write %d entries to %s", len(manifest), baseline_path)
        return
    comparator = BaselineComparator(scanner=scanner)
    comparator.save_baseline(baseline_path, manifest)
    logging.getLogger(__name__).info("Baseline saved: %s (%d files)", baseline_path, len(manifest))


def cmd_monitor(config: dict, dry_run: bool) -> None:
    """Run the FIM monitoring loop with graceful shutdown."""
    from pxguard.core.monitor import FileMonitor

    shutdown = {"stop": False}

    def stop_event() -> bool:
        return shutdown["stop"]

    def on_signal(_signum, _frame) -> None:
        shutdown["stop"] = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    monitor = FileMonitor(config, dry_run=dry_run, stop_event=stop_event)
    monitor.run()


def cmd_simulate(config: dict, args: argparse.Namespace) -> None:
    """Run the ransomware simulator (safe: only in allowed root)."""
    from pxguard.simulator.ransomware_simulator import run_simulation

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path
    config_path = config_path.resolve()
    run_simulation(
        project_root=config["project_root"],
        allowed_root=config["simulator_allowed_root"],
        config_path=config_path,
    )


def main() -> int:
    """CLI logic (unchanged from original)."""
    _default_config = Path(__file__).resolve().parent / "config" / "config.yaml"
    parser = argparse.ArgumentParser(
        prog="pxguard",
        description="File Integrity Monitoring (FIM) for Linux - detect unauthorized file modifications.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=str(_default_config),
        help="Path to config.yaml (default: package config; use CWD-relative or absolute)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write baseline or alerts; only scan/compare.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-baseline", help="Create baseline from current state of monitored directories")
    sub.add_parser("monitor", help="Start continuous FIM monitoring")
    sub.add_parser("simulate-attack", help="Run ransomware simulator in test directory")

    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    try:
        config = get_config(args)
    except FileNotFoundError as e:
        logging.getLogger(__name__).error("%s", e)
        return 1
    except Exception as e:
        logging.getLogger(__name__).exception("Failed to load config: %s", e)
        return 1

    if args.command == "init-baseline":
        cmd_init_baseline(config, args.dry_run)
    elif args.command == "monitor":
        cmd_monitor(config, args.dry_run)
    elif args.command == "simulate-attack":
        cmd_simulate(config, args)
    else:
        parser.print_help()
        return 0
    return 0


def cli() -> None:
    """Entry point for the pxguard console command."""
    sys.exit(main())
