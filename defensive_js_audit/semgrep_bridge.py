#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reliable Semgrep JSON bridge with deterministic health testing."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

BRIDGE_VERSION = "2.0.0"
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_RULE_TIMEOUT_SEC = 25
DEFAULT_MAX_TARGET_BYTES = 2_000_000

PACK_TO_RULES = {
    "domxss": ["p/javascript", "p/owasp-top-ten"],
    "secrets": ["p/secrets"],
    "crypto": ["p/javascript", "p/security-audit"],
}

SELF_TEST_RULE_ID = "bridge.health.eval"
SELF_TEST_RULE = """rules:
  - id: bridge.health.eval
    message: Semgrep bridge health-check finding
    severity: ERROR
    languages: [javascript]
    pattern: eval(...)
"""
SELF_TEST_JS = 'const bridgeValue = "2 + 2";\neval(bridgeValue);\n'


def emit(obj):
    try:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    except Exception as exc:
        print(json.dumps({"ok": False, "bridge_ok": False, "error": "json-emit-failed", "detail": str(exc), "results": []}))


def run_process(cmd, timeout_sec):
    started = time.monotonic()
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout_sec)),
            shell=False,
        )
        return {
            "started": True,
            "timed_out": False,
            "returncode": p.returncode,
            "stdout": p.stdout or "",
            "stderr": p.stderr or "",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "started": True,
            "timed_out": True,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "exception": "timeout",
        }
    except Exception as exc:
        return {
            "started": False,
            "timed_out": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "exception": "%s: %s" % (type(exc).__name__, exc),
        }


def parse_json(raw):
    text = (raw or "").strip()
    if not text:
        return None, "empty-stdout"
    try:
        obj = json.loads(text)
    except Exception:
        first, last = text.find("{"), text.rfind("}")
        if first < 0 or last <= first:
            return None, "invalid-json"
        try:
            obj = json.loads(text[first:last + 1])
        except Exception:
            return None, "invalid-json"
    if not isinstance(obj, dict):
        return None, "json-root-not-object"
    if not isinstance(obj.get("results", []), list):
        obj["results"] = []
    return obj, None


def candidates(explicit=None):
    out = []
    if explicit:
        out.append(("explicit", [explicit]))
    out.append(("semgrep", [shutil.which("semgrep") or "semgrep"]))
    out.append(("python-module", [sys.executable, "-m", "semgrep"]))
    seen, deduped = set(), []
    for name, prefix in out:
        key = tuple(prefix)
        if key not in seen:
            seen.add(key)
            deduped.append((name, prefix))
    return deduped


def discover_semgrep(explicit=None):
    attempts = []
    for name, prefix in candidates(explicit):
        result = run_process(prefix + ["--version"], 15)
        attempts.append({
            "runner": name,
            "command": prefix + ["--version"],
            "started": result["started"],
            "timed_out": result["timed_out"],
            "returncode": result["returncode"],
            "stdout": (result.get("stdout") or "")[:1000],
            "stderr": (result.get("stderr") or "")[:1000],
            "exception": result.get("exception"),
        })
        version = (result.get("stdout") or result.get("stderr") or "").strip()
        if result["started"] and not result["timed_out"] and result["returncode"] == 0 and version:
            return {"available": True, "runner": name, "prefix": prefix, "version": version.splitlines()[0], "attempts": attempts}
    return {"available": False, "runner": None, "prefix": None, "version": None, "attempts": attempts}


def health_check(explicit=None, timeout_sec=30):
    discovery = discover_semgrep(explicit)
    result = {
        "ok": False,
        "bridge_ok": True,
        "health_check": True,
        "bridge_version": BRIDGE_VERSION,
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "semgrep_available": discovery["available"],
        "semgrep_runner": discovery["runner"],
        "semgrep_version": discovery["version"],
        "json_ok": False,
        "local_rule_ok": False,
        "expected_finding_ok": False,
        "results": [],
        "discovery_attempts": discovery["attempts"],
    }
    if not discovery["available"]:
        result["error"] = "semgrep-not-available"
        return result

    with tempfile.TemporaryDirectory(prefix="semgrep-bridge-health-") as td:
        rule_path = os.path.join(td, "health.yml")
        target_path = os.path.join(td, "health.js")
        with open(rule_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(SELF_TEST_RULE)
        with open(target_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(SELF_TEST_JS)

        cmd = discovery["prefix"] + ["--json", "--quiet", "--no-error", "--config", rule_path, target_path]
        process = run_process(cmd, timeout_sec)
        data, error = parse_json(process.get("stdout"))
        result.update({
            "command": cmd,
            "returncode": process["returncode"],
            "timed_out": process["timed_out"],
            "stderr": (process.get("stderr") or "")[:3000],
            "json_ok": data is not None,
        })
        if data is None:
            result["error"] = error
            return result
        result["results"] = data.get("results", [])
        result["local_rule_ok"] = not any("invalid" in str(e).lower() for e in data.get("errors", []))
        result["expected_finding_ok"] = SELF_TEST_RULE_ID in [r.get("check_id") for r in data.get("results", [])]
        result["ok"] = bool(result["json_ok"] and result["local_rule_ok"] and result["expected_finding_ok"] and not result["timed_out"])
        if not result["ok"]:
            result["error"] = "health-check-finding-not-verified"
        return result


def build_configs(packs):
    configs, unknown = [], []
    for pack in packs:
        name = (pack or "").strip().lower()
        if not name:
            continue
        if name not in PACK_TO_RULES:
            unknown.append(name)
        else:
            configs.extend(PACK_TO_RULES[name])
    deduped, seen = [], set()
    for config in configs:
        if config not in seen:
            seen.add(config)
            deduped.append(config)
    return deduped, unknown


def scan(target, packs, timeout_sec, rule_timeout_sec, max_target_bytes, explicit=None):
    discovery = discover_semgrep(explicit)
    if not discovery["available"]:
        return {"ok": False, "bridge_ok": True, "error": "semgrep-not-available", "results": [], "discovery_attempts": discovery["attempts"]}

    configs, unknown = build_configs(packs)
    if unknown:
        return {"ok": False, "bridge_ok": True, "error": "unknown-packs", "unknown_packs": unknown, "results": []}
    if not configs:
        return {"ok": False, "bridge_ok": True, "error": "no-configs", "results": []}

    cmd = discovery["prefix"] + ["--json", "--quiet", "--no-error", "--timeout", str(rule_timeout_sec), "--max-target-bytes", str(max_target_bytes)]
    for config in configs:
        cmd += ["--config", config]
    cmd.append(target)

    process = run_process(cmd, timeout_sec)
    data, error = parse_json(process.get("stdout"))
    if data is None:
        return {
            "ok": False,
            "bridge_ok": True,
            "error": error,
            "results": [],
            "runner": discovery["runner"],
            "semgrep_version": discovery["version"],
            "returncode": process["returncode"],
            "timed_out": process["timed_out"],
            "stderr": (process.get("stderr") or "")[:5000],
        }

    return {
        "ok": not process["timed_out"],
        "bridge_ok": True,
        "target": target,
        "packs": packs,
        "configs": configs,
        "results": data.get("results", []),
        "errors": data.get("errors", []),
        "paths": data.get("paths", {}),
        "runner": discovery["runner"],
        "semgrep_version": discovery["version"],
        "returncode": process["returncode"],
        "timed_out": process["timed_out"],
        "stderr": (process.get("stderr") or "")[:5000],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--health-check", action="store_true")
    ap.add_argument("--target")
    ap.add_argument("--packs", default="")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SEC)
    ap.add_argument("--rule-timeout", type=int, default=DEFAULT_RULE_TIMEOUT_SEC)
    ap.add_argument("--max-target-bytes", type=int, default=DEFAULT_MAX_TARGET_BYTES)
    ap.add_argument("--semgrep-path")
    args, _unknown = ap.parse_known_args()

    if args.health_check:
        emit(health_check(args.semgrep_path, max(5, args.timeout)))
        return
    if not args.target:
        emit({"ok": False, "bridge_ok": True, "error": "missing-target", "results": []})
        return
    if not os.path.isfile(args.target):
        emit({"ok": False, "bridge_ok": True, "error": "target-not-found", "target": args.target, "results": []})
        return

    packs = [x.strip() for x in args.packs.split(",") if x.strip()]
    emit(scan(args.target, packs, max(5, args.timeout), max(1, args.rule_timeout), max(1024, args.max_target_bytes), args.semgrep_path))


if __name__ == "__main__":
    main()
