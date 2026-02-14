# PXGuard

**File Integrity Monitoring (FIM) for Linux** — detect unauthorized file modifications and simulate early ransomware detection.

| | |
|---|---|
| **Author** | phoenixoOor |
| **Language** | Python 3.11+ |
| **OS** | Linux (Ubuntu) |

---

## Overview

PXGuard is a modular, production-style FIM tool for Blue Team operations. It maintains a cryptographic baseline of monitored directories and periodically rescans to detect:

- **Modified** files (hash mismatch)
- **Deleted** files
- **Newly created** files
- **Renamed** files (inferred from hash reuse)

A threshold engine raises **CRITICAL** alerts when many changes occur in a short time window, mimicking ransomware burst behavior.

---

## Architecture

```
project_root/
├── pyproject.toml
├── README.md
├── requirements.txt
├── test_assets/             # Optional; monitored if in config
└── pxguard/                 # Installable package
    ├── __init__.py
    ├── main.py              # CLI entry (pxguard = pxguard.main:cli)
    ├── core/                # FIM engine
    │   ├── hashing.py
    │   ├── scanner.py
    │   ├── comparator.py
    │   ├── alerts.py
    │   ├── thresholds.py
    │   ├── config_loader.py
    │   ├── monitor.py
    │   └── models.py
    ├── simulator/
    │   └── ransomware_simulator.py
    ├── config/
    │   └── config.yaml      # Default config (paths relative to CWD)
    ├── baseline/            # Generated baseline.json (when using default config)
    └── logs/                # Generated alerts.log (when using default config)
```

**Data flow**

1. **Baseline creation**: `DirectoryScanner` walks configured dirs, `HashEngine` hashes each file, result stored in `baseline.json`.
2. **Monitoring**: `FileMonitor` loads baseline, rescans at `scan_interval`, `BaselineComparator` diff produces `FIMEvent` list.
3. **Threshold**: `ThresholdTracker` keeps a sliding window of event timestamps; if count exceeds `change_count` in `time_window_seconds`, events are escalated to CRITICAL.
4. **Alerting**: `AlertManager` appends JSON to `logs/alerts.log` and optionally prints colored lines to stderr.

---

## Detection Logic

| Scenario | Detection |
|----------|-----------|
| File in baseline, not in current scan | **DELETED** |
| File in current scan, not in baseline | **CREATED** (or **RENAMED** if hash matches a single deleted path) |
| Same path in both, different hash | **MODIFIED** |
| Many events in short window | Severity escalated to **CRITICAL** (threshold) |

Paths in the baseline and current manifest are stored relative to the project root with a directory prefix (e.g. `test_assets/sample.txt`) so multiple monitored directories stay distinct.

---

## Configuration

The package ships a default config at `pxguard/config/config.yaml`. Override with `--config`. Paths in the config are relative to the current working directory (where you run `pxguard`) unless absolute.

- **monitoring.directories**: List of directories to monitor.
- **monitoring.scan_interval**: Seconds between comparison cycles.
- **monitoring.exclude_patterns**: Glob-style patterns to skip (e.g. `*.log`, `.git/*`).
- **thresholds.change_count** / **time_window_seconds**: Max changes in window before CRITICAL.
- **alerts.log_path**, **console_alerts**, **min_severity**.
- **paths.baseline_file**: Where to store/load the baseline.
- **simulator.allowed_root**: Only directory the simulator is allowed to modify.

---

## Installation

Install as an editable package so the `pxguard` command is available:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Then run:

```bash
pxguard --help
pxguard init-baseline
pxguard monitor
pxguard simulate-attack
```

Paths in `config/config.yaml` are resolved relative to the **current working directory** (where you run `pxguard`). Run from your project root so that `config/`, `baseline/`, and `logs/` resolve correctly.

---

## How to Run

### 1. Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. Create baseline

Capture the current state of monitored directories (e.g. `./baseline`, `./test_assets`):

```bash
pxguard init-baseline
```

Optional: `--dry-run` to only scan and report what would be written; no file changes.

### 3. Start monitor

Run continuous FIM; compare against baseline every `scan_interval` seconds:

```bash
pxguard monitor
```

- Alerts go to `logs/alerts.log` (JSON lines) and, if enabled, to the console.
- Stop with **Ctrl+C** or SIGTERM; shutdown is graceful.

Optional: `--dry-run` to run compare cycles without writing alerts or changing state.

### 4. Simulate ransomware

**Only modifies files under `simulator.allowed_root` (default: `./test_assets`).** Do not point this at real data.

```bash
pxguard simulate-attack
```

The simulator either Base64-encodes file contents or renames with `.locked`. Its actions are logged; PXGuard monitor will see MODIFIED/CREATED/DELETED and, if many changes in a short window, CRITICAL threshold alerts. **Note:** In base64 mode, empty files stay empty (base64 of empty is empty); add some content to files in `test_assets` if you want to see visible changes.

---

## Example log output

**Console (stderr):**

```
[WARNING] MODIFIED: test_assets/sample.txt
[CRITICAL] MODIFIED: test_assets/another.txt
```

**logs/alerts.log (one JSON object per line):**

```json
{"timestamp": "2025-02-12T14:30:00.123456+00:00", "event_type": "MODIFIED", "file_path": "test_assets/sample.txt", "severity": "WARNING"}
{"timestamp": "2025-02-12T14:30:00.124000+00:00", "event_type": "MODIFIED", "file_path": "test_assets/another.txt", "severity": "CRITICAL", "metadata": {"threshold_exceeded": true}}
```

---

## Incident response

1. **Single MODIFIED/DELETED/CREATED**  
   Investigate the file and path; confirm whether the change is authorized. Restore from backup or rebuild from source if needed.

2. **CRITICAL (threshold exceeded)**  
   Treat as possible ransomware or mass change. Isolate the host, stop the monitor if it’s safe to do so, and follow your incident response playbook (forensics, containment, recovery).

3. **Baseline refresh**  
   After validating the system, update the baseline:  
   `pxguard init-baseline`  
   Then restart monitoring.

---

## License and disclaimer

PXGuard is for authorized security testing and monitoring only. Use only in environments you are allowed to scan and modify. The ransomware simulator is for testing FIM and must only be run against dedicated test directories.
