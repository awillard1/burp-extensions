# Defensive JS Audit (Burp Extension)

Defensive JS Audit is a **Burp Suite extension** for passive and manual auditing of JavaScript/HTML responses, focused on vulnerability analyst workflows.

It combines:

- A built-in **heuristic detection engine** (no Semgrep required)
- Optional **Semgrep bridge** integration via a Python helper
- Burp-native issue reporting with practical triage guidance
- DOM XSS validation support with **DOM Invader** workflow helpers

---

## Features

### Core scanning (built-in, no external dependencies)
- Detects high-risk JavaScript patterns such as:
  - Dynamic code execution (`eval`, `new Function`, string-based timers)
  - DOM XSS sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`)
  - `javascript:` URL usage
  - postMessage misconfiguration and missing origin checks
  - Token storage issues (`localStorage` / `sessionStorage`)
  - Weak crypto primitives (e.g., SHA-1/MD5 references, weak cipher references)
  - Framework-specific XSS sink patterns (React/Vue/Angular)
  - Open redirect/source-to-sink heuristics
  - SQL construction heuristics
  - Hard-coded secret/token patterns + entropy-based secret detection

### HTML + inline JavaScript coverage
- Scans:
  - Full JavaScript responses
  - HTML markup rules
  - Inline `<script>` blocks
  - Inline event handlers (`onclick=...`, etc.)
  - `javascript:` attribute payloads

### Burp workflow integration
- Passive capture via selectable Burp tools:
  - Proxy
  - Repeater
  - Scanner
  - (optional) Intruder / extension-generated traffic
- Context menu action:
  - **“Defensive JS Audit - scan response”** for manual one-off scans
- In-scope filtering support (`callbacks.isInScope(URL)`)

### Analyst-focused extras
- Severity filtering (Critical/High/Medium/Low/Info)
- Built-in DOM Invader checklist copy button
- Rich issue details with source/sink remediation guidance
- De-duplication and caching to reduce scan noise

### Optional Semgrep bridge
- External helper (`semgrep_bridge.py`) with:
  - Deterministic health check
  - Rule pack selection (`domxss`, `secrets`, `crypto`)
  - Timeouts and target size controls
  - Async queueing with configurable parallelism (1–4 jobs)

---

## Repository contents

- `defensive_js_audit.py`  
  Main Burp extension implementation (UI, rule engine, passive/manual scan orchestration, issue generation, optional Semgrep scheduling).

- `semgrep_bridge.py`  
  Python helper that runs Semgrep reliably and emits normalized JSON for extension consumption.

---

## Requirements

## Core extension
- Burp Suite (Extender support)
- Jython-compatible runtime for Burp Python extensions (for `defensive_js_audit.py`)

## Optional Semgrep integration
- Python 3 executable
- Semgrep installed and runnable
- Valid path to `semgrep_bridge.py`

> Core detection works without Semgrep. Semgrep is optional and can be enabled from the extension UI.

---

## Installation

1. Open Burp Suite.
2. Go to **Extender → Extensions**.
3. Add `defensive_js_audit.py` as a Python extension.
4. Confirm the tab **“JS Audit”** appears.

---

## Configuration (JS Audit tab)

### Severity and scan toggles
- Select severities to report.
- Enable/disable:
  - Automatic response scanning
  - In-scope-only passive scans
  - JS scanning
  - HTML scanning
  - Source→sink heuristic

### Tool capture toggles
Choose which Burp tools feed passive captures:
- Proxy
- Repeater
- Scanner
- Intruder (optional)
- Extension-generated responses (optional)

### Semgrep (optional)
1. Enable **“Semgrep bridge (optional)”**
2. Set:
   - Python 3 path
   - `semgrep_bridge.py` path
   - Timeout
   - Max parallel jobs
   - Packs (`domxss`, `secrets`, `crypto`)
3. Click **“Test Semgrep bridge”** to verify health before scanning.

---

## Usage

### Passive mode
When enabled, responses are scanned automatically based on:
- selected tools
- scope setting
- content classification (JS/HTML)

### Manual mode
Right-click a response and select:

**Defensive JS Audit - scan response**

Manual mode forces a scan and logs results in the extension panel.

---

## What gets reported

Findings are added as Burp issues with:
- Rule ID and category
- Engine severity + Burp severity mapping
- Approximate line number
- Matched code/snippet
- Analyst remediation guidance

For XSS/source-to-sink categories, issue details include explicit **DOM Invader testing guidance**.

---

## Performance and safety controls

- Response body cap (`MAX_BODY_BYTES`)
- Max matches per rule (`MAX_MATCHES_PER_RULE`)
- Max issues per response (`MAX_ISSUES_PER_RESPONSE`)
- Cache-based de-duplication and TTL eviction
- Optional async Semgrep queue with bounded queue depth

---

## Notes

- This extension is designed for **analyst triage and guided validation**, not proof of exploitability by itself.
- Heuristic findings should be manually confirmed before formal reporting.
- Secret/token hits should be treated as potentially live until verified otherwise.

---

## Disclaimer

Use only on systems and applications you are authorized to test.
