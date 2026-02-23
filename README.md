# PXGuard Technical Documentation

**Version:** 1.0.0
**Classification:** Internal / Investor-Ready
**Last Updated:** February 2026

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [Detection Engine](#3-detection-engine)
4. [Alerting System](#4-alerting-system)
5. [Dashboard](#5-dashboard)
6. [State Management](#6-state-management)
7. [Security Design Decisions](#7-security-design-decisions)
8. [Threat Model](#8-threat-model)
9. [Limitations](#9-limitations)
10. [Risks and Gaps](#10-risks-and-gaps)
11. [Future Roadmap](#11-future-roadmap)
12. [Deployment Model](#12-deployment-model)
13. [Executive Summary](#13-executive-summary)

---

## 1. Product Overview

### What PXGuard Is

PXGuard is a host-based file integrity monitoring (FIM) system for Linux with lightweight endpoint detection and response (EDR) capabilities. It continuously monitors designated directories for unauthorized file changes, attributes detected modifications to responsible processes, analyzes the process ancestry for indicators of compromise, and triggers automated response when warranted.

### Problem Statement

Traditional FIM solutions detect *that* a file changed but not *who* changed it or *why* the change is suspicious. Administrators receive an alert stating a configuration file was modified, then spend investigative effort correlating logs, process tables, and audit records to determine whether the change was legitimate. Ransomware, cryptominers, and post-exploitation toolkits frequently modify or delete files in bulk before any manual triage can begin.

PXGuard closes this gap by combining four capabilities that are typically isolated across separate products:

1. **Integrity verification** -- cryptographic hashing (SHA-256) against a known-good baseline.
2. **Process attribution** -- identifying the PID, binary path, user, and command line of the process responsible for each change.
3. **Ancestry analysis** -- walking the process tree to detect suspicious parent chains (reverse shells, /tmp execution, privilege escalation patterns).
4. **Automated response** -- optional process termination for CRITICAL-severity events when a resolved, non-protected process is identified.

### Positioning

PXGuard occupies a deliberate position between pure FIM (OSSEC, AIDE, Tripwire) and full EDR platforms (CrowdStrike Falcon, Carbon Black, Elastic Defend):

| Capability | Traditional FIM | PXGuard | Full EDR |
|---|---|---|---|
| File change detection | Yes | Yes | Yes |
| Process attribution | No | Yes (heuristic + inotify) | Yes (kernel hooks) |
| Parent chain analysis | No | Yes (psutil) | Yes (kernel telemetry) |
| Automated response | No | Yes (optional) | Yes |
| Kernel instrumentation | No | No | Yes (eBPF/kprobes) |
| Deployment complexity | Low | Low | High |
| Resource overhead | Minimal | Low | Moderate-High |

PXGuard is designed for teams that need process-aware file monitoring without the operational burden of deploying a kernel-level agent, and for environments where a lightweight footprint is preferred over exhaustive syscall tracing.

### Design Philosophy

1. **Low false positives over high recall.** Every detection rule is designed to avoid attributing file changes to unrelated processes. Shells, IDEs, and system daemons are penalized or ignored in scoring. The system prefers reporting `[UNKNOWN_PROCESS]` over making a wrong attribution.

2. **Controlled escalation.** Severity transitions from OK to WARNING to CRITICAL follow deterministic, auditable rules. Escalation to CRITICAL requires either sustained abnormal activity (consecutive anomalous scans) or behavioral indicators (suspicious parent chain). A single file deletion does not trigger CRITICAL.

3. **Graceful degradation.** Every external dependency (psutil, inotify, Rich, Plotly, watchdog) is probed at import time. If unavailable, the system degrades to the next-best capability: no psutil means no process attribution; no Rich means ANSI dashboard; no inotify means polling-only detection.

4. **No crashes from protected processes.** Every `psutil` call is individually wrapped in try/except for `AccessDenied`, `NoSuchProcess`, and `ZombieProcess`. A single unkillable kernel thread or zombie never halts the monitoring pipeline.

---

## 2. Architecture Overview

### High-Level Architecture

```
                    +------------------+
                    |   CLI (main.py)  |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  config_loader   |   <-- config.yaml + .env (SMTP creds)
                    +--------+---------+
                             |
           +-----------------v------------------+
           |          FileMonitor (monitor.py)  |
           +-----------------+------------------+
                             |
     +-----------+-----------+-----------+-----------+
     |           |           |           |           |
+----v----+ +---v----+ +----v----+ +----v----+ +----v----+
| Scanner | |Compara-| |Threshold| |Anomaly  | | Event   |
| (hash)  | |  tor   | | Tracker | | Engine  | | Capture |
+---------+ +--------+ +---------+ +---------+ |(inotify)|
                                                +---------+
                             |
                    +--------v---------+
                    | Process Resolver |  <-- multi-strategy PID attribution
                    +--------+---------+
                             |
                    +--------v---------+
                    | Process Tree     |  <-- parent chain (up to depth 10)
                    |   Builder        |
                    +--------+---------+
                             |
                    +--------v---------+
                    | Parent Analyzer  |  <-- suspicious parent detection
                    +--------+---------+
                             |
                    +--------v---------+
                    | Reaction Engine  |  <-- optional SIGTERM/SIGKILL
                    +--------+---------+
                             |
              +--------------v--------------+
              |       Alert Service         |
              |  +--------+  +-----------+  |
              |  |JSON log|  |Email Alert|  |
              |  +--------+  +-----------+  |
              +-----------------------------+
```

### Pipeline Execution Order

Each scan cycle executes the following stages in strict sequence:

```
scan_directories  -->  load_baseline  -->  compare (CREATED/MODIFIED/DELETED/RENAMED)
       |
       v
threshold_tracker.record_and_escalate  (volume-based WARNING -> CRITICAL)
       |
       v
anomaly_engine.evaluate  (state machine: NORMAL / SUSPICIOUS / ATTACK)
       |
       v
process_resolver.resolve_batch  (open_files + cmdline + CWD heuristics)
       |
       v
capture_cache lookup  (inotify real-time fallback for exited processes)
       |
       v
process_tree_builder.build  (parent chain walk via ppid)
       |
       v
parent_analyzer.analyze  (behavioral rules -> severity escalation)
       |
       v
reaction_engine.react  (optional: terminate CRITICAL processes)
       |
       v
alert_manager.emit_batch  +  notifier.send_incident  (if anomaly and cooldown expired)
```

### Core Modules and Responsibilities

| Module | Responsibility |
|---|---|
| `main.py` | CLI parser, signal handling, subcommands (init-baseline, monitor, simulate-attack) |
| `config_loader.py` | YAML parsing, path resolution, SMTP env-var validation |
| `scanner.py` | Recursive directory traversal, SHA-256 manifest generation |
| `hashing.py` | Chunked SHA-256 computation (8 KB blocks) |
| `comparator.py` | Baseline diff: produces CREATED, MODIFIED, DELETED, RENAMED events |
| `thresholds.py` | Sliding-window change rate tracking with cooldown |
| `anomaly_engine.py` | Three-state machine (NORMAL/SUSPICIOUS/ATTACK), spike detection, cooldown |
| `process_resolver.py` | Multi-strategy PID resolution with scoring, penalties, and fallbacks |
| `event_capture.py` | Linux inotify daemon thread for real-time process capture |
| `process_tree_builder.py` | Parent chain construction via ppid traversal (max depth 10) |
| `parent_analyzer.py` | Behavioral rules for suspicious parent detection |
| `reaction_engine.py` | SIGTERM/SIGKILL automated response for CRITICAL events |
| `monitor.py` | Orchestrator: wires all pipeline stages, runs scan loop |
| `alerts.py` | Structured JSON logging and colored console output |
| `notifier.py` | Email orchestrator: coordinates ReportBuilder and EmailService |
| `report_builder.py` | Jinja2 HTML and plain-text report rendering |
| `email_service.py` | SMTP/TLS transport, MIME message assembly |
| `report.py` | Session summary report (text) |
| `report_engine.py` | Security incident report (text) |
| `rich_dashboard.py` | Rich-based live dashboard (Threat Summary, Activity Monitor, Alerts) |
| `dashboard.py` | ANSI fallback dashboard |
| `graph.py` | ChangeGraph (Plotly HTML / matplotlib PNG), TerminalGraph |
| `graph_engine.py` | CyberActivityGraph (Rich renderable), Braille graph, security graph export |
| `watchdog_handler.py` | Optional watchdog filesystem observer with debouncing |
| `ransomware_simulator.py` | Safe test utility: Base64-encodes or renames files under allowed root |
| `models.py` | Shared data models: FIMEvent, EventType, Severity |

---

## 3. Detection Engine

### 3.1 File Integrity Monitoring

#### Mechanism

PXGuard uses a baseline-comparison model. A known-good state of the filesystem is captured as a JSON manifest mapping each file path to its SHA-256 hash, file size, and last-modified timestamp. On each scan cycle, the current filesystem state is rehashed and compared against this baseline.

The hashing engine (`hashing.py`) reads files in 8192-byte chunks to bound memory usage regardless of file size. SHA-256 was chosen for its cryptographic collision resistance and ubiquity in compliance frameworks (PCI DSS, NIST 800-53).

#### Baseline Generation

```bash
pxguard init-baseline
```

The `DirectoryScanner` recursively traverses all configured directories, applying glob-based exclusion patterns (e.g., `*.log`, `*.tmp`, `.git/*`, `__pycache__/*`). Paths are stored relative to the monitored directory to allow baseline portability. The resulting manifest is serialized to JSON and written to the configured baseline path.

#### Change Classification

The `BaselineComparator.compare()` method produces four event types:

| Event | Condition | Default Severity |
|---|---|---|
| `DELETED` | File present in baseline but absent in current scan | WARNING |
| `CREATED` | File present in current scan but absent in baseline | INFO |
| `MODIFIED` | File present in both but SHA-256 hash differs | WARNING |
| `RENAMED` | New file path with identical hash to a single deleted file | INFO |

Rename detection uses a hash-to-path index: if a newly appearing file has the same SHA-256 as exactly one disappearing file, it is classified as RENAMED rather than generating separate CREATED and DELETED events. The matched hash is consumed to prevent duplicate rename attributions.

#### Event Capture Layer

PXGuard operates in two concurrent modes:

1. **Polling mode (primary).** The `FileMonitor` rescans all directories at a configurable interval (default: 10 seconds). This is the authoritative detection mechanism -- every scan cycle produces a complete and consistent view of the filesystem.

2. **Real-time inotify capture (supplementary).** An `EventCaptureThread` daemon thread uses Linux `inotify` (accessed via `ctypes` -- no external dependencies) to receive kernel notifications of file creation, modification, deletion, and movement in real time. When an event fires, the thread immediately invokes `ProcessResolver.resolve_batch()` and caches the resulting `ProcessInfo` in a thread-safe TTL cache (`ProcessCaptureCache`).

The inotify layer exists for one purpose: capturing the PID of short-lived processes (e.g., `rm`, single-shot scripts) that exit before the next polling cycle. The main scan loop queries the capture cache only for events where the primary `psutil` scan could not attribute a process. inotify watches are added recursively to all subdirectories; newly created directories receive watches automatically.

If inotify is unavailable (non-Linux platforms, file descriptor limits), the system degrades to polling-only with no process attribution for exited processes. A warning is logged but operation continues.

#### Optional Watchdog Integration

When `watchdog_enabled: true` is set in configuration, PXGuard starts a `watchdog.Observer` alongside the inotify capture thread. The watchdog handler debounces filesystem events and triggers an early scan cycle rather than waiting for the polling interval to expire. This reduces detection latency from `scan_interval` seconds to the debounce window (default: 2 seconds).

The watchdog layer is event-driven but does not replace the polling comparator. It functions as a scan trigger, not a detection mechanism.


### 3.2 Process Attribution

#### PID Resolution Strategy

Process attribution in a polling-based FIM is inherently a best-effort problem. By the time the scanner detects a file change, the process responsible may have already closed the file handle and exited. PXGuard addresses this with a multi-strategy approach implemented in `ProcessResolver.resolve_batch()`.

The resolver scans the process table exactly once per batch (via `psutil.process_iter()`), evaluating three strategies against every target file in a single pass:

**Strategy 1: Open Files (Definitive, Score = 100)**

If a process currently holds an open file descriptor for the target file, it is definitively the modifier. This check uses `proc.open_files()` and resolves symlinks for accurate comparison. Processes with more than 500 open file descriptors (typically browsers, databases) are skipped for this strategy to avoid performance degradation.

**Strategy 2: Command Line (Strong Heuristic, Score = 30-50)**

The resolver checks whether the target file path or its parent directory appears in the process command line (`proc.cmdline()`). A full file path match scores 50; a parent directory match scores 30. This catches commands like `rm /path/to/file` or `python3 /path/to/script.py` that are still running.

**Strategy 3: Working Directory (Moderate Heuristic, Score = 4-25)**

The resolver compares the process CWD (`proc.cwd()`) to the target file's parent directory. Exact parent match scores 25; within 3 levels of nesting scores 10; deeper ancestry scores 4. This is the weakest heuristic and relies heavily on penalty modifiers to avoid false positives.

#### Scoring, Penalties, and Confidence

Each candidate process accumulates a score from the strategies above. The highest-scoring process above a minimum confidence threshold (8) is selected.

To control false positives, penalty multipliers are applied to heuristic matches (Strategies 2 and 3):

- **Shell penalty (0.4x):** Processes named `bash`, `zsh`, `fish`, etc. have their heuristic scores multiplied by 0.4. Every interactive terminal shares the user's project directory as CWD, so without this penalty, the user's shell would be attributed to nearly every change.
- **IDE penalty (0.3x):** Processes named `cursor`, `code`, `pycharm`, etc. receive a 0.3x multiplier. IDEs keep the project root as CWD and hold many files open for indexing, but are rarely the direct modification source.
- **Ignored names:** System daemons (`systemd`, `sshd`, `dbus-daemon`, `udevd`, etc.) are skipped entirely -- they never modify user files.

A **recency bonus** of up to 4 points is added for processes created within the last 30 seconds, and 2 points for those within 120 seconds. This breaks ties between a long-running shell and a freshly spawned `rm` command sharing the same CWD.

#### Fallback: Filesystem Owner

When no process exceeds the confidence threshold and real-time capture has no cached result, the resolver falls back to identifying the filesystem owner of the target file's parent directory via `os.stat()` and `pwd.getpwuid()`. This produces a `ProcessInfo` with `pid=None` (not considered "resolved" for reaction purposes) but `username` set, displayed as `[user: phoenix]` rather than a blank `[UNKNOWN_PROCESS]`.

#### Limitations

- **Ephemeral processes.** Commands that execute and exit in under ~100ms (e.g., `rm`, `mv`) may exit before both the inotify capture thread and the next polling cycle can attribute them. The recency bonus and inotify cache mitigate but do not eliminate this.
- **No kernel-level attribution.** Without eBPF or audit subsystem hooks, PXGuard cannot guarantee that the process it identifies is the one that performed the specific write syscall. Two processes with the same file open simultaneously are indistinguishable at the psutil level.
- **Container and namespace boundaries.** `psutil` reads `/proc` from the host namespace. PXGuard running inside a container may not see processes in the host PID namespace, and vice versa.


### 3.3 Suspicious Parent Detection

#### Overview

The `ParentAnalyzer` examines the full process ancestry (parent chain) of every resolved process. This module was designed to detect post-exploitation techniques where a malicious process is spawned by a network listener, runs from a staging directory, or exhibits privilege escalation patterns.

The `ProcessTreeBuilder` constructs the chain by repeatedly calling `psutil.Process(pid).ppid()`, capturing a snapshot (`TreeNode`) of each ancestor: PID, name, executable path, username, and command line. The walk terminates at PID 1 (init/systemd), when a cycle is detected (via a visited-PID set), or when depth exceeds 10.

#### Detection Rules

Five independent rules are evaluated against the tree. Any single rule firing causes the event to be escalated to CRITICAL.

**Rule 1: Suspicious Process Name**

The name (lowercase) of every node in the tree is checked against a curated set of known offensive tools:

- Network tools: `ncat`, `nc`, `netcat`, `socat`
- Scanning: `nmap`, `masscan`, `zmap`
- Post-exploitation: `meterpreter`, `msfconsole`, `msfvenom`, `cobalt`, `beacon`
- Credential theft: `mimikatz`, `lazagne`, `crackmapexec`
- Tunneling: `chisel`, `ligolo`, `plink`
- Cryptomining: `xmrig`, `minerd`, `cpuminer`
- Ransomware families: `cryptolocker`, `wannacry`, `locky`

**Rule 2: Temporary Directory Execution**

If any process in the chain has its executable (`proc.exe()`) path under `/tmp/`, `/dev/shm/`, `/var/tmp/`, or `/run/user/`, the event is flagged. Legitimate software is almost never executed from these locations; they are commonly used as malware staging directories because they are world-writable and often mounted without `noexec`.

**Rule 3: Uncommon Home Directory Execution**

Processes running from `/home/` are flagged if their name is not in an exception list of known legitimate tools (shells, editors, version control, interpreters, IDEs). This catches attacker-dropped binaries executed from a compromised user's home directory.

**Rule 4: Interpreter Spawned by Network Listener**

This is a compound rule targeting reverse shell patterns. If a child process is an interpreter (`python`, `python3`, `perl`, `ruby`, `node`, `php`, `lua`) and its immediate parent is a network listener (`ncat`, `nc`, `socat`, `sshd`, `nginx`, etc.), the event is flagged. This pattern is a strong indicator of a reverse shell or web shell execution chain (e.g., `ncat -l 4444 -e /bin/bash` -> `python3 -c 'import socket...'`).

**Rule 5: Privilege Escalation**

If the direct child process runs as `root` but its parent runs as a non-root user, the event is flagged as a potential privilege escalation. This detects SUID exploitation, sudo abuse, and similar techniques where a low-privilege process spawns a high-privilege child without going through expected system mechanisms.

#### Escalation Logic

When any rule fires, the `ParentAnalysis` result has `escalate_to_critical = True`. The monitor sets the event's severity to `Severity.CRITICAL` and tags its metadata with `parent_escalated: true` and the list of reasons. This ensures the event is processed by the reaction engine and included prominently in email reports.


### 3.4 Severity Model

PXGuard uses three severity levels with distinct semantic meanings:

#### INFO

Assigned to events that represent expected or benign filesystem changes:
- `CREATED` -- a new file appeared in a monitored directory.
- `RENAMED` -- an existing file was moved within the monitored tree.

INFO events are logged but do not trigger threshold counting, anomaly evaluation, or email alerts.

#### WARNING (Volume-Based)

The default severity for file changes that may indicate unauthorized activity:
- `MODIFIED` -- file content hash changed.
- `DELETED` -- file was removed from a monitored directory.

WARNING is a *volume-neutral* severity. A single MODIFIED file is WARNING. Ten MODIFIED files are also WARNING individually, but the *aggregate count* may trigger escalation.

#### CRITICAL (Behavior-Based)

Assigned through two independent escalation paths:

**Path 1: Volume-based escalation (ThresholdTracker)**

The `ThresholdTracker` maintains a sliding window of event timestamps (default: 60-second window). When the count of events in the window meets or exceeds the configured threshold (default: 10), all events in the current batch are escalated to CRITICAL. A cooldown period (default: 60 seconds) prevents repeated escalation on every subsequent scan while the attack continues.

The cooldown exits when either (a) the cooldown timer expires, or (b) the event count drops below the threshold. This means a sustained attack generates exactly one CRITICAL escalation per cooldown window, not one per scan cycle.

**Path 2: Behavioral escalation (ParentAnalyzer)**

When the parent analysis detects a suspicious ancestry chain (any of the five rules described in Section 3.3), the event is escalated to CRITICAL regardless of volume. A single file modification by a process descended from `ncat` is immediately CRITICAL.

#### State Machine: Threat Level Transitions

The `AnomalyEngine` maintains an independent three-state machine that drives the dashboard threat level and email alert logic:

```
               static_exceeded OR spike_detected
    NORMAL  ──────────────────────────────────────>  SUSPICIOUS
      ^                                                  |
      |          count drops, no abnormal                |  2+ consecutive
      +──────────────────────────────────────────────────+  abnormal scans
                                                         |
                                                         v
                                                      ATTACK
```

- **NORMAL** -> dashboard shows `OK`. No email.
- **SUSPICIOUS** -> dashboard shows `WARNING`. Email sent if cooldown expired.
- **ATTACK** -> dashboard shows `CRITICAL`. Email sent if cooldown expired.

The state transitions are:
- `NORMAL -> SUSPICIOUS`: current scan total exceeds the static threshold OR exceeds `mean(last 5 scans) * 2.0` (spike detection).
- `SUSPICIOUS -> ATTACK`: two or more consecutive abnormal scans (sustained activity, not a single spike).
- `ATTACK -> NORMAL`: consecutive abnormal counter resets to 0 when a scan has no abnormal indicators.
- `SUSPICIOUS -> NORMAL`: same condition as above.

#### Re-Alert Rules

Email alerts are rate-limited by a cooldown timer (default: 300 seconds / 5 minutes). The `AnomalyEngine.evaluate()` method returns `is_anomaly = True` only when:

1. The current state is `SUSPICIOUS` or `ATTACK`, AND
2. The cooldown timer has expired since the last alert.

When `is_anomaly = True`, the monitor generates a security report, exports a graph snapshot, and sends an incident email. The cooldown timer is then reset. This design guarantees:

- **No alert spam:** A sustained 30-minute attack generates at most 6 emails (one every 5 minutes), not one per scan cycle.
- **Category transition re-alert:** If the system was in `SUSPICIOUS` (WARNING email sent, cooldown started), and then escalates to `ATTACK` within the cooldown window, the ATTACK-state email is deferred until cooldown expires. The email that fires after cooldown will reflect the escalated state.
- **Recovery detection:** When the system returns to `NORMAL`, no email is sent. The dashboard simply shows `OK`.

---

## 4. Alerting System

### 4.1 Structured Logging

Every FIM event is written as a JSON line to the configured log file (`alerts.log`) by the `AlertManager`:

```json
{
  "timestamp": "2026-02-22T22:31:32.451234+00:00",
  "event_type": "DELETED",
  "file_path": "test_assets/folder_1/hello.txt",
  "severity": "CRITICAL",
  "metadata": {"threshold_exceeded": true}
}
```

Events below the configured `min_severity` are silently dropped. The log file is append-only and human-readable.

Console alerts use colorama for cross-platform colored output: red for CRITICAL, yellow for WARNING, green for INFO/OK.

### 4.2 Email Alert Pipeline

The email system is structured as three layers with strict separation of concerns:

**Layer 1: ReportBuilder** (`report_builder.py`)

Pure data-in, string-out. Takes an `IncidentContext` dataclass containing all incident metrics and renders:
- HTML email body via Jinja2 template (`templates/email_report.html`) with dark-theme styling, severity badges, incident summary table, changed file list, automated action log, process tree visualization, and embedded graph.
- Plain-text fallback for email clients that do not render HTML.

**Layer 2: EmailService** (`email_service.py`)

Pure SMTP transport. Assembles MIME multipart messages with:
- `multipart/mixed` root
  - `multipart/alternative` (plain text + related HTML)
    - `text/plain` -- fallback
    - `multipart/related` (HTML + inline graph image)
      - `text/html` -- rendered template
      - `image/png` -- activity graph (Content-ID embedded)
  - `text/plain` attachment -- full security report text file

Supports STARTTLS, configurable host/port, and app-password authentication.

**Layer 3: IncidentNotifier** (`notifier.py`)

Orchestrator. Reads the security report from disk, determines whether a graph image is available for embedding, constructs the `IncidentContext`, delegates rendering to `ReportBuilder`, delegates transport to `EmailService`. Returns `True/False` to the caller -- never raises.

### 4.3 Email Contents

Each incident email includes:

| Section | Content |
|---|---|
| Header | Severity badge (CRITICAL/WARNING/OK with color coding) |
| Incident Summary | Threat level, anomaly state, created/modified/deleted counts, total changes, threshold, cooldown, total scans, peak changes, timestamp |
| Activity Graph | Inline PNG (CID-embedded) showing file change trends over scan iterations |
| Changed Files | Up to 25 file paths with event type and color coding |
| Automated Actions | Reaction engine results: action taken, PID, process name, success/failure, detail |
| Process Trees | Full parent chain visualization with SUSPICIOUS/CLEAN badges and detection reasons |
| Explanation | Brief context for the recipient |
| Footer | Generation timestamp |

### 4.4 SMTP Credential Security

SMTP credentials are never stored in `config.yaml`. They are loaded exclusively from environment variables (`PXGUARD_SMTP_HOST`, `PXGUARD_SMTP_PORT`, `PXGUARD_SMTP_USER`, `PXGUARD_SMTP_PASSWORD`), sourced from a `.env` file via `python-dotenv`. The `.env` file is excluded from version control via `.gitignore`.

The `config_loader` validates that all four variables are present and non-empty when `email_alerts_enabled: true`. If any are missing, a descriptive `RuntimeError` is raised at startup rather than failing silently during an incident.

### 4.5 Graph Generation

Two graph systems produce visual artifacts:

**Interactive Plotly HTML** (`change_graph.html`)

Generated at session end. Four series (Created, Modified, Deleted, Total) plotted against scan iteration with dark theme, interactive zoom/pan, and threshold reference line. Used for post-incident analysis.

**Security Report Graph** (PNG + HTML)

Generated per incident (when anomaly is detected). Includes spike markers (diamond symbols) at anomaly indices. The PNG is embedded in the incident email; the HTML is saved alongside the text report for browser-based review.

Both graphs use exclusively real scan data. No dummy values, simulated data, or placeholder points are ever plotted.

### 4.6 Report Artifacts

Each anomaly event generates two files in the log directory:

- `security_report_YYYYMMDD_HHMMSS.txt` -- structured incident report with timestamp, scan counts, peak metrics, threshold, anomaly state, and final status.
- `security_report_YYYYMMDD_HHMMSS.png` / `.html` -- activity graph snapshot at the time of the incident.

At session end, a `report_summary.txt` is written with aggregate session metrics.

---

## 5. Dashboard

### 5.1 Rich Dashboard (Primary)

When a TTY is detected and the `rich` library is available, PXGuard renders a live terminal dashboard with three panels:

**Threat Summary Panel** (left, top)

Displays current scan metrics: total files scanned, created/modified/deleted counts, total changes, configured threshold, current threat level (OK/WARNING/CRITICAL with color coding), and a threat meter progress bar (`[████████░░░░░░░░] 50%`). An audible beep (`\a`) is emitted on the first transition to CRITICAL.

**Activity Monitor Panel** (right, top)

A cybersecurity-themed real-time graph (`CyberActivityGraph`) showing the last 60 scan iterations as vertical bars with:
- Bottom-up rendering (bars grow upward from the baseline).
- Vertical gradient using Unicode block characters: `░` (safe), `▒` (risk), `▓`/`█` (critical).
- Color zones: bright cyan (safe), magenta (near threshold), bright red with blink (above threshold).
- Laser-style threshold line (`═`) overlaid.
- Y-axis labels in hexadecimal format.
- `[ DATA_STREAM: ACTIVE ]` indicator (green when safe, red blink when critical).
- Breathing behavior: when three consecutive scans report zero changes, the Y-axis scale gradually contracts so the threshold line remains visible.

**Recent Alerts Panel** (bottom, full width)

Tabular display of the last 10 alert entries with columns: Time, Severity, SOURCE (process attribution in dim yellow), and Message. The SOURCE column displays the resolved process identifier (e.g., `1234 [python3]`) or `[UNKNOWN_PROCESS]` when attribution failed. Events flagged by the parent analyzer append `[SUSPICIOUS PARENT]` to the message.

All dashboard data comes from real scan results. No values are simulated, interpolated, or hard-coded.

### 5.2 Plain Dashboard (Fallback)

When Rich is unavailable or `dashboard.interactive: false`, PXGuard falls back to an ANSI-based dashboard that clears and redraws on each scan cycle, showing file counts and status with color coding. A `TerminalGraph` renders change counts as ASCII bar charts or `plotext` line plots below the summary.

### 5.3 Refresh Behavior

The Rich dashboard uses `rich.live.Live` with `auto_refresh=False`. The layout is re-rendered and explicitly pushed via `live.update()` after each scan cycle completes. The refresh rate is set to 4 Hz for smooth visual transitions. Stderr logging is suppressed during Rich dashboard operation to prevent interference with the live layout.

---

## 6. State Management

### 6.1 Baseline State

The filesystem baseline is stored as a JSON file (`baseline/baseline.json`) mapping relative file paths to records:

```json
{
  "test_assets/folder_1/file_1.txt": {
    "hash": "a3f2b8c...",
    "size": 1024,
    "last_modified": 1740200000.0
  }
}
```

The baseline is loaded at the start of each scan cycle and compared against the current filesystem state. It is only modified by the explicit `pxguard init-baseline` command, never by the monitoring loop. This immutability is intentional: the baseline represents the known-good state, and any deviation from it is a detection event.

### 6.2 Anomaly Engine State

The `AnomalyEngine` maintains per-instance state (no global or file-persisted state):

- `_state`: Current state (`NORMAL`, `SUSPICIOUS`, or `ATTACK`).
- `_recent_totals`: Deque of the last N scan totals (default N=10) for spike detection mean calculation.
- `_consecutive_abnormal`: Count of consecutive scans classified as abnormal (static threshold exceeded or spike detected).
- `_cooldown_until`: Monotonic timestamp after which the next alert can fire.

This state is volatile -- it resets when PXGuard restarts. This is by design: each monitoring session starts from a clean state. Persistent state tracking across sessions is not currently implemented.

### 6.3 Threshold Tracker State

The `ThresholdTracker` maintains:

- `_timestamps`: Deque of monotonic timestamps of all events within the current time window.
- `_cooldown_until`: Monotonic timestamp marking the end of the current cooldown period after a threshold alert.

Old timestamps are pruned on each evaluation (`_prune_old()`). Cooldown exits when the timer expires OR the event count drops below the threshold.

### 6.4 Session Metrics

The `FileMonitor` tracks cumulative session metrics:

- `_session_total_scans`: Total scan cycles completed.
- `_session_max_changes`: Maximum change count observed in any single scan.
- `_session_peak_iteration`: Scan iteration number at which the peak occurred.
- `_session_peak_timestamp`: Wall-clock time of the peak.
- `_session_final_status`: Last known threat level (OK/WARNING/CRITICAL).

These are written to `report_summary.txt` at session end.

### 6.5 Process Capture Cache

The `ProcessCaptureCache` is a thread-safe dictionary mapping resolved file paths to `(ProcessInfo, timestamp)` tuples with a configurable TTL (default: `scan_interval * 3`). Entries older than the TTL are evicted on access. The cache bridges the inotify daemon thread and the main scan loop.

---

## 7. Security Design Decisions

### 7.1 Why Heuristic Process Attribution

Definitive process-to-file-change attribution requires kernel-level instrumentation (eBPF, fanotify with FAN_REPORT_FID, or audit subsystem rules). PXGuard deliberately avoids kernel hooks to minimize deployment friction, privilege requirements, and system stability risk. The heuristic approach via `psutil` is correct in many practical scenarios (process still running, file still open, command line visible) and provides actionable information even when imperfect.

The scoring system with penalties and confidence thresholds was designed to avoid a specific failure mode: attributing every file change to the user's shell or IDE, which are always running with CWD in the project directory. Without penalties, `bash` would score 25 on CWD proximity for every file in the project, producing 100% false attribution. The 0.4x shell penalty reduces this to 10, well below the confidence threshold of 8 for CWD-only matches, ensuring shells are only attributed when stronger evidence exists (command line match at 20+, or open file handle at 100).

### 7.2 Why Not Full EDR

Full EDR products intercept syscalls at the kernel level, providing complete and authoritative attribution for every file operation. PXGuard does not pursue this for three reasons:

1. **Kernel module risk.** A buggy kernel module or eBPF program can panic the system. PXGuard is designed for environments where stability is paramount.
2. **Privilege requirement.** eBPF and fanotify require `CAP_SYS_ADMIN` or root. PXGuard can run as any user that has read access to the monitored directories and `/proc`.
3. **Deployment simplicity.** PXGuard installs via `pip install` with no kernel headers, DKMS compilation, or reboot required.

### 7.3 False Positive Control

The system prioritizes specificity over sensitivity at every decision point:

- **Process attribution:** Below-threshold scores produce `[UNKNOWN_PROCESS]` rather than a wrong PID.
- **Parent analysis:** The suspicious name list is curated to include only tools with near-zero legitimate use in production file operations. Common sysadmin tools (`ssh`, `rsync`, `git`) are explicitly excluded from home-directory flagging.
- **Threshold escalation:** A single file change is never CRITICAL on volume alone. The threshold requires a sustained burst (default: 10 changes in 60 seconds).
- **Anomaly state machine:** ATTACK requires two consecutive abnormal scans, not one. A single spike returns to NORMAL on the next clean scan.

### 7.4 Performance Considerations

- **Single-pass process table scan.** `resolve_batch()` iterates `psutil.process_iter()` once for all target files, regardless of whether 1 or 100 files changed. Cost is O(P * F) where P is the number of processes and F is the number of changed files, but F is bounded by the file count and P is bounded by the system process count.
- **FD count guard.** Processes with more than 500 file descriptors skip the `open_files()` strategy. This prevents pathological slowdowns when scanning systems running browsers or databases with thousands of open handles.
- **inotify buffer batching.** The capture thread reads inotify events in 8192-byte buffers and resolves all files in the buffer in a single `resolve_batch()` call, amortizing process table iteration.
- **TTL cache eviction.** The capture cache evicts entries lazily on access, avoiding expensive periodic cleanup sweeps.

---

## 8. Threat Model

### 8.1 What PXGuard Detects

| Attack Type | Detection Mechanism |
|---|---|
| **Ransomware (file encryption)** | Bulk MODIFIED events trigger threshold escalation to CRITICAL. SHA-256 changes on all files indicate content replacement. |
| **Data destruction (mass deletion)** | Bulk DELETED events trigger threshold escalation. |
| **Configuration tampering** | Individual MODIFIED events on monitored config files at WARNING severity. |
| **Web shell deployment** | CREATED event in monitored web directory. If the deploying process has a suspicious parent chain (e.g., spawned by `nginx`/`apache2`), escalated to CRITICAL. |
| **Reverse shell execution** | Parent analysis detects interpreter-spawned-by-listener pattern (e.g., `python3` child of `ncat`). |
| **Malware staging in /tmp** | Parent analysis flags any process in the chain executing from `/tmp`, `/dev/shm`, or `/var/tmp`. |
| **Privilege escalation** | Parent analysis detects root child process spawned by non-root parent. |
| **Cryptominer deployment** | Parent analysis flags known miner process names (`xmrig`, `minerd`, `cpuminer`). |
| **Post-exploitation tools** | Parent analysis flags `meterpreter`, `cobalt`, `beacon`, `mimikatz`, `lazagne`, etc. in the process chain. |

### 8.2 What PXGuard Does Not Detect

| Attack Type | Why Not |
|---|---|
| **In-memory attacks (fileless malware)** | PXGuard monitors filesystem state. Attacks that execute entirely in memory without modifying monitored files are invisible. |
| **Kernel rootkits** | A rootkit that manipulates `/proc` or the VFS layer can hide file changes and processes from userspace tools. |
| **Slow-drip exfiltration** | Reading files (data exfiltration) does not change hashes. PXGuard detects modification, not access. |
| **Legitimate bulk operations** | A deployment script that modifies 50 configuration files will trigger threshold escalation. Whitelisting or baseline refresh is required. |
| **Process injection** | An attacker injecting code into a legitimate process (e.g., `LD_PRELOAD` hooking) is indistinguishable from the legitimate process at the `psutil` level. |
| **Race condition exploitation** | TOCTOU attacks between `open_files()` check and actual write are possible but impractical to exploit for evasion purposes. |

### 8.3 Expected Deployment Model

PXGuard is designed for:

- Linux servers hosting web applications, APIs, or microservices where configuration and application files should not change outside deployment windows.
- Development/staging environments where unauthorized modifications to test assets or build artifacts need detection.
- Compliance-driven environments (PCI DSS Requirement 11.5, NIST 800-53 SI-7) requiring file integrity monitoring with process-level attribution.

PXGuard runs as a persistent daemon process, started via systemd, supervisor, or a terminal session.

---

## 9. Limitations

### 9.1 Process Attribution Race Conditions

The fundamental limitation of userspace process attribution is timing. A process that:
1. Opens a file,
2. Writes to it,
3. Closes the file handle, and
4. Exits

...all within the inotify capture thread's resolution latency (~10-50ms) may not be attributed. The inotify thread detects the event instantly, but `psutil.process_iter()` may not return results fast enough before the process terminates.

In practice, this affects single-shot commands like `rm` and `truncate` that complete in under 1ms. Multi-file operations (ransomware, scripts processing directories) take long enough for at least one attribution to succeed.

### 9.2 No Kernel Hooks

PXGuard does not use eBPF, fanotify (FAN_REPORT_FID), kprobes, or the Linux audit subsystem. This means:
- No guaranteed syscall-level attribution.
- No detection of `ptrace`-based process injection.
- No visibility into memory-mapped file writes that bypass standard `write()` syscalls.

### 9.3 No Syscall Interception

PXGuard does not intercept or block filesystem syscalls. It is a *detection* system, not a *prevention* system. The reaction engine can terminate processes after detection, but cannot prevent the initial write from occurring.

### 9.4 Baseline Staleness

The baseline must be manually refreshed after legitimate changes (deployments, configuration updates). Stale baselines generate persistent false-positive MODIFIED events on every scan cycle.

### 9.5 Single-Host Scope

PXGuard monitors the local filesystem of the host it runs on. It has no centralized management, fleet-wide visibility, or cross-host correlation. Each instance operates independently.

### 9.6 Volatile State

All anomaly engine state, threshold tracking, and session metrics are in-memory. A PXGuard restart resets the anomaly state to NORMAL and clears all cooldown timers. An attacker who can restart the PXGuard process can reset its detection state.

---

## 10. Risks and Gaps

This section documents honest architectural weaknesses and areas for improvement identified during analysis.

### 10.1 Anomaly State Not Persisted Across Restarts

If PXGuard is restarted (intentionally or by an attacker), the anomaly state resets to NORMAL. The `_recent_totals` deque, `_consecutive_abnormal` counter, and cooldown timers are lost. An attacker could theoretically kill and restart PXGuard between attacks to prevent ATTACK state accumulation.

**Recommendation:** Persist anomaly state to a file or database. Implement tamper detection on the state file.

### 10.2 No Self-Protection Mechanism

PXGuard does not monitor its own process for termination or tampering. An attacker with sufficient privileges can `kill -9` the PXGuard process, modify files at will, then allow PXGuard to be restarted. The session report will show a clean start.

**Recommendation:** Implement a watchdog supervisor (systemd `Restart=always` at minimum) and alert on unexpected restarts. Consider self-integrity monitoring of the PXGuard binary and configuration.

### 10.3 Email Delivery Is Best-Effort

SMTP failures are logged but not retried. If the mail server is unreachable during an incident (e.g., network-level attack), the alert email is silently lost. The security report and graph are still written to disk.

**Recommendation:** Implement a retry queue with exponential backoff. Consider alternative notification channels (webhook, Slack, PagerDuty) as fallback.

### 10.4 Threshold Cooldown May Defer Critical Alerts

If the threshold cooldown is set too high (e.g., 300 seconds) and a volume-based CRITICAL event occurs during cooldown, the email is deferred until cooldown expires. This is by design (anti-spam), but could delay notification of a genuine escalation within an ongoing incident.

**Recommendation:** Consider a separate "escalation" path that bypasses cooldown when severity transitions from WARNING to CRITICAL (category change re-alert).

### 10.5 No Test Suite

The codebase does not include automated unit tests, integration tests, or CI/CD pipeline configuration. Correctness relies on manual testing via the ransomware simulator and visual dashboard inspection.

**Recommendation:** Implement pytest-based test suite covering: comparator logic, threshold state machine, anomaly engine transitions, process resolver scoring, parent analyzer rules, and email rendering.

### 10.6 Rename Detection Is Approximate

Rename detection uses SHA-256 hash matching: if a new file has the same hash as exactly one deleted file, it is classified as RENAMED. This fails when:
- Multiple files have identical content (the hash matches more than one deleted file).
- A file is renamed and modified in the same scan cycle (hash changes, so it appears as DELETE + CREATE).

### 10.7 No Rate Limiting on Reaction Engine

The reaction engine attempts to terminate every CRITICAL-resolved process without rate limiting. In a scenario with 1000 CRITICAL events per scan, the engine would attempt 1000 `kill()` syscalls in rapid succession. While each is individually safe, the aggregate impact on system load is uncontrolled.

**Recommendation:** Implement per-scan and per-PID rate limiting in the reaction engine.

---

## 11. Future Roadmap

### 11.1 eBPF Integration

Replace or supplement `psutil`-based attribution with eBPF programs attached to `vfs_write`, `vfs_unlink`, and `vfs_rename` tracepoints. This would provide guaranteed, kernel-level attribution with zero race conditions.

### 11.2 Ransomware Entropy Detection

Compute Shannon entropy of modified file contents. Encrypted files exhibit entropy near 8.0 bits/byte (indistinguishable from random data). A sudden jump in average file entropy across a directory is a strong ransomware indicator, detectable before the threshold count is reached.

### 11.3 Quarantine Mode

Instead of terminating a process, move the affected files to a quarantine directory (preserving metadata) and block further writes via file permissions. This allows forensic analysis without data loss.

### 11.4 MITRE ATT&CK Mapping

Map each detection rule to MITRE ATT&CK technique IDs:
- Suspicious parent names: T1059 (Command and Scripting Interpreter)
- /tmp execution: T1074.001 (Data Staged: Local Data Staging)
- Interpreter from listener: T1059.004 (Unix Shell) + T1071 (Application Layer Protocol)
- Privilege escalation: T1068 (Exploitation for Privilege Escalation)

### 11.5 Confidence Scoring

Replace boolean SUSPICIOUS/CLEAN with a continuous confidence score (0.0-1.0) that aggregates all rule results, weighting each by its false-positive rate in production telemetry.

### 11.6 Centralized Management

Agent-server architecture where multiple PXGuard instances report to a central dashboard with fleet-wide visibility, cross-host correlation, and centralized policy management.

### 11.7 Persistent State and Tamper Detection

Persist anomaly state, cooldown timers, and session metrics to an HMAC-signed state file. Detect tampering on load and alert if the state file was modified externally.

### 11.8 Alternative Notification Channels

Support webhook-based alerting (Slack, Microsoft Teams, PagerDuty, Opsgenie) as primary or fallback channels alongside SMTP email.

---

## 12. Deployment Model

### 12.1 System Requirements

| Requirement | Specification |
|---|---|
| Operating System | Linux (kernel 2.6.13+ for inotify; tested on Ubuntu 22.04+) |
| Python | 3.11 or later |
| Privileges | Read access to monitored directories, read access to `/proc` for process attribution. Root not required unless reaction engine needs to terminate other users' processes. |
| Memory | ~50 MB baseline + ~1 MB per 10,000 monitored files |
| Disk | Log files, graphs, and reports accumulate in the configured log directory |

### 12.2 Installation

```bash
pip install -e .
```

Or from requirements:

```bash
pip install -r requirements.txt
```

### 12.3 Configuration

Configuration is loaded from `pxguard/config/config.yaml` (or a custom path via `--config`).

```yaml
monitoring:
  directories:
    - ./test_assets            # Directories to monitor (relative to CWD)
  scan_interval: 10            # Seconds between scan cycles
  exclude_patterns:            # Glob patterns to exclude
    - "*.log"
    - "*.tmp"
    - ".git/*"

thresholds:
  change_count: 10             # Events to trigger CRITICAL
  time_window_seconds: 60      # Sliding window for threshold
  cooldown_seconds: 60         # Cooldown after threshold alert

dashboard:
  interactive: true            # Use Rich dashboard (false = ANSI fallback)
  history_size: 30             # Scan iterations to retain

alerts:
  log_path: ./pxguard/logs/alerts.log
  console_alerts: true
  min_severity: INFO           # Minimum severity to log
  email_alerts_enabled: true
  email_to: "security@example.com"
  attach_visuals: true

reaction:
  enabled: false               # Enable automated process termination
```

### 12.4 Email Setup

1. Create a `.env` file in the project root (copy from `.env.example`):

```bash
PXGUARD_SMTP_HOST=smtp.gmail.com
PXGUARD_SMTP_PORT=587
PXGUARD_SMTP_USER=your_bot@gmail.com
PXGUARD_SMTP_PASSWORD=your_app_password
```

2. Set `email_alerts_enabled: true` and `email_to:` in `config.yaml`.

3. PXGuard performs an SMTP health check (connect + STARTTLS + login) at startup. If authentication fails, email is disabled with a warning log rather than crashing the monitor.

### 12.5 Usage

```bash
# Generate initial baseline
pxguard init-baseline

# Start monitoring
pxguard monitor

# Run ransomware simulation (safe: only modifies test_assets/)
pxguard simulate-attack

# Verbose logging
pxguard -v monitor

# Dry run (no writes to baseline or logs)
pxguard monitor --dry-run
```

### 12.6 Threshold Tuning Guidelines

| Environment | Recommended Threshold | Rationale |
|---|---|---|
| Static production server | 3-5 changes / 60s | Configuration files rarely change outside deployments |
| Active development | 20-50 changes / 60s | Frequent saves and builds |
| CI/CD pipeline | Disable email, use log analysis | High-volume legitimate changes |
| Honeypot/canary files | 1 change / 60s | Any modification is suspicious |

### 12.7 Signal Handling

PXGuard registers handlers for `SIGINT` and `SIGTERM` for graceful shutdown. On signal reception:
1. The scan loop exits cleanly.
2. The inotify capture thread is stopped.
3. Watchdog observer (if active) is stopped and joined.
4. Final session report and change graph are written.
5. Log files are flushed.

---

## 13. Executive Summary

**PXGuard** is a file integrity monitoring system for Linux that goes beyond traditional hash-based detection by attributing file changes to specific processes, analyzing process ancestry for indicators of compromise, and optionally terminating malicious processes in real time.

**The problem:** Organizations need to know not just *that* files changed, but *who* changed them and *whether the change is malicious*. Traditional FIM tools detect the symptom; PXGuard investigates the cause.

**How it works:** PXGuard maintains a cryptographic baseline of monitored files and compares it against the live filesystem every 10 seconds. When changes are detected, a multi-strategy engine identifies the responsible process by examining open file handles, command lines, and working directories across the entire process table. The process's parent chain is then walked and analyzed against behavioral rules that detect reverse shells, malware staging, privilege escalation, and known offensive tools. Events are classified as OK, WARNING, or CRITICAL through a dual-path escalation model: volume-based (too many changes too fast) and behavior-based (suspicious process ancestry).

**Key differentiators:**

- **Process-aware detection.** Every file change is attributed to a PID, binary, user, and full parent chain -- not just a hash delta.
- **Behavioral escalation.** A single file change by a process spawned from `ncat` is immediately CRITICAL, regardless of volume.
- **Real-time capture.** A Linux inotify thread captures process attribution for short-lived commands that exit before the next scan cycle.
- **Low deployment friction.** Installs via `pip`, runs as any user, requires no kernel modules or root privileges for monitoring.
- **Automated response.** Optional process termination for CRITICAL events, with protection for system-critical processes.

**What it produces:** Live terminal dashboard with threat meter and process-attributed alert log, structured JSON event logs, dark-themed HTML email reports with embedded graphs and process tree visualizations, and timestamped security incident reports.

**Deployment model:** Single-host daemon process. Configured via YAML. SMTP credentials via environment variables. Threshold tuning for environment-specific sensitivity. Compatible with systemd service management.

**Current maturity:** Functional v1.0 with active development. Core detection engine, process attribution, parent analysis, email alerting, and dashboard are production-quality. Areas for investment include eBPF-based kernel attribution, entropy-based ransomware detection, centralized fleet management, and automated test coverage.

---

*PXGuard -- File Integrity Monitoring with Process Intelligence.*
*Copyright 2026. All rights reserved.*
