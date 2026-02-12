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
pxguard/
├── core/                    # FIM engine
│   ├── hashing.py           # SHA256 file hashing
│   ├── scanner.py           # Recursive directory scan + manifest
│   ├── comparator.py        # Baseline vs current comparison → events
│   ├── alerts.py            # JSON log + optional console alerts
│   ├── thresholds.py        # Change-rate → CRITICAL escalation
│   ├── config_loader.py     # config.yaml load + path resolution
│   ├── monitor.py           # FileMonitor: scan loop + compare + alert
│   └── models.py            # FIMEvent, EventType, Severity dataclasses
├── config/
│   └── config.yaml          # Directories, interval, exclusions, thresholds
├── baseline/
│   └── baseline.json        # Generated: path → { hash, size, last_modified }
├── logs/
│   └── alerts.log           # One JSON object per line
├── simulator/
│   └── ransomware_simulator.py   # Safe simulation under test dir only
└── main.py                  # CLI: init-baseline | monitor | simulate-attack
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

Edit `config/config.yaml`. No hardcoded paths; all paths are relative to the project root unless absolute.

- **monitoring.directories**: List of directories to monitor.
- **monitoring.scan_interval**: Seconds between comparison cycles.
- **monitoring.exclude_patterns**: Glob-style patterns to skip (e.g. `*.log`, `.git/*`).
- **thresholds.change_count** / **time_window_seconds**: Max changes in window before CRITICAL.
- **alerts.log_path**, **console_alerts**, **min_severity**.
- **paths.baseline_file**: Where to store/load the baseline.
- **simulator.allowed_root**: Only directory the simulator is allowed to modify.

---

## How to Run

### 1. Install dependencies

```bash
cd pxguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Create baseline

Capture the current state of monitored directories (e.g. `./baseline`, `./test_assets`):

```bash
python main.py init-baseline
```

Optional: `--dry-run` to only scan and report what would be written; no file changes.

### 3. Start monitor

Run continuous FIM; compare against baseline every `scan_interval` seconds:

```bash
python main.py monitor
```

- Alerts go to `logs/alerts.log` (JSON lines) and, if enabled, to the console.
- Stop with **Ctrl+C** or SIGTERM; shutdown is graceful.

Optional: `--dry-run` to run compare cycles without writing alerts or changing state.

### 4. Simulate ransomware

**Only modifies files under `simulator.allowed_root` (default: `./test_assets`).** Do not point this at real data.

```bash
python main.py simulate-attack
```

The simulator either Base64-encodes file contents or renames with `.locked`. Its actions are logged; PXGuard monitor will see MODIFIED/CREATED/DELETED and, if many changes in a short window, CRITICAL threshold alerts.

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
   `python main.py init-baseline`  
   Then restart monitoring.

---

## License and disclaimer

PXGuard is for authorized security testing and monitoring only. Use only in environments you are allowed to scan and modify. The ransomware simulator is for testing FIM and must only be run against dedicated test directories.
