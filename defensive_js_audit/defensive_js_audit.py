# -*- coding: utf-8 -*-
"""
Defensive JS Audit - Burp Suite Extension (Heuristic + Optional Semgrep bridge)
===============================================================================
Improved for vulnerability analysts:
- More reliable path handling on Windows (Java File APIs instead of fragile os.path)
- Stronger token/key/secret detection with better FP resistance
- Expanded sinks + improved source->sink heuristics
- Clearer analyst-oriented reporting + DOM Invader guidance on XSS findings
- Passive + context-menu scanning of JS / HTML / inline scripts / event handlers / javascript: URLs
- Fixed in-scope/out-of-scope handling for passive capture
- Added analyst helper button to copy DOM Invader testing checklist/payloads

No Semgrep required for core detection.
Optional Semgrep via external Python3 helper script.
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import ITab
from burp import IContextMenuFactory
from burp import IHttpListener

from java.io import PrintWriter, File
from java.util import ArrayList
from javax.swing import (
    JPanel, JCheckBox, JLabel, JButton, JScrollPane, JTextArea, JTextField,
    BoxLayout, BorderFactory, SwingUtilities, JMenuItem
)
from java.awt import Font, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener

import re
import math
import json
import tempfile
import subprocess
import hashlib
import time
from collections import OrderedDict

EXTENSION_NAME = "Defensive JS Audit"
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_MATCHES_PER_RULE = 12
MAX_ISSUES_PER_RESPONSE = 500

BURP_HIGH = "High"
BURP_MEDIUM = "Medium"
BURP_LOW = "Low"
BURP_INFO = "Information"

SEV_TO_BURP = {
    "critical": BURP_HIGH,
    "high": BURP_HIGH,
    "medium": BURP_MEDIUM,
    "low": BURP_LOW,
    "info": BURP_INFO,
}

# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

def _compile(patterns, flags=re.I | re.M):
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p, flags))
        except Exception:
            pass
    return out

RULES = []

def _add(rule_id, title, severity, confidence, detail, fix, patterns, category="general"):
    RULES.append({
        "id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "detail": detail,
        "fix": fix,
        "patterns": _compile(patterns),
        "category": category,
    })

# --- Code execution ---
_add("JS-EVAL-001", "Dynamic code execution (eval / Function / setTimeout string)",
     "high", "medium",
     "Dynamic evaluation can enable code injection if attacker-controlled data reaches these APIs.",
     "Avoid eval / new Function / setTimeout(string). Prefer Function constructors only with trusted input or safer alternatives.",
     [r"\beval\s*\(", r"\bnew\s+Function\s*\(", r"\bsetTimeout\s*\(\s*['\"`]", r"\bsetInterval\s*\(\s*['\"`]"],
     "code-execution")

_add("JS-EVAL-002", "Indirect eval / Function via bracket or apply",
     "high", "low",
     "Obfuscated or indirect dynamic execution often used to evade simple scanners.",
     "Search for the resolved callee and remove dynamic execution paths.",
     [r"\bwindow\s*\[\s*['\"]eval['\"]\s*\]", r"\bFunction\s*\[\s*['\"]constructor['\"]\s*\]",
      r"\beval\s*\.\s*call\s*\(", r"\beval\s*\.\s*apply\s*\("],
     "code-execution")

# --- DOM XSS sinks ---
_add("JS-DOM-XSS-001", "DOM XSS sink (innerHTML / outerHTML / insertAdjacentHTML / document.write)",
     "high", "medium",
     "Unsafe HTML sinks can lead to DOM XSS when fed untrusted data.",
     "Prefer textContent / innerText. Sanitize with a maintained library (DOMPurify) if HTML is required. Test with DOM Invader.",
     [r"\.\s*innerHTML\s*=", r"\.\s*outerHTML\s*=", r"\binsertAdjacentHTML\s*\(", r"\bdocument\.write(?:ln)?\s*\("],
     "xss")

_add("JS-DOM-XSS-002", "DOM XSS via srcdoc",
     "high", "medium",
     "Assigning untrusted content to iframe.srcdoc executes script in the frame context.",
     "Never assign untrusted HTML to srcdoc. Use sandbox + strict CSP.",
     [r"\.\s*srcdoc\s*="], "xss")

_add("JS-DOM-XSS-003", "DOM XSS via jQuery / $ HTML methods",
     "medium", "medium",
     "jQuery .html() / .append() etc. are classic DOM XSS sinks.",
     "Prefer .text(). Sanitize if HTML is required. Test reflected sources with DOM Invader.",
     [r"\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\s*\("],
     "xss")

_add("JS-DOM-XSS-004", "DOM property sinks (location / href / src / action)",
     "medium", "low",
     "Assignment to navigation or resource-loading properties can cause XSS or open redirects when data is attacker-controlled.",
     "Validate / allowlist destinations. Prefer safer navigation APIs where possible.",
     [r"(?:location\.(?:href|assign|replace)|window\.location|\.href|\.src|\.action)\s*[=\(]",
      r"\blocation\s*=\s*"],
     "xss")

_add("JS-URL-JS-001", "javascript: URL usage",
     "high", "high",
     "javascript: URLs execute script in navigation and many attribute contexts.",
     "Block javascript: schemes. Use data: or proper event handlers only with trusted content.",
     [r"['\"`]javascript\s*:"], "xss")

# --- Messaging / storage ---
_add("JS-POSTMSG-001", "postMessage with wildcard targetOrigin",
     "medium", "high",
     "targetOrigin '*' allows any origin to receive the message (data leak / further attack surface).",
     "Always specify an exact origin. Validate event.origin on the receiving side.",
     [r"\bpostMessage\s*\([^,]+,\s*['\"]\*['\"]\s*[\),]"], "postmessage")

_add("JS-POSTMSG-002", "postMessage listener without origin check",
     "medium", "low",
     "MessageEvent handlers that do not check event.origin are a common XSS / data-exfil vector.",
     "Always verify event.origin against an allowlist before processing data.",
     [r"addEventListener\s*\(\s*['\"]message['\"]\s*,", r"\.onmessage\s*="],
     "postmessage")

_add("JS-STORAGE-001", "Sensitive token-like data written to storage",
     "medium", "low",
     "Tokens in localStorage / sessionStorage are readable by any XSS payload on the origin.",
     "Prefer HttpOnly + Secure + SameSite cookies for session secrets. Avoid storing long-lived tokens in JS-accessible storage.",
     [r"(?:local|session)Storage\s*\.\s*setItem\s*\(\s*['\"`][^'\"`]*(?:token|jwt|secret|auth|session|password|apikey|api[_-]?key|access[_-]?token|refresh[_-]?token)[^'\"`]*['\"`]"],
     "storage")

_add("JS-COOKIE-001", "document.cookie assignment",
     "low", "low",
     "Cookies set from JavaScript cannot be HttpOnly and are therefore XSS-readable.",
     "Set sensitive cookies server-side with HttpOnly + Secure + SameSite.",
     [r"document\.cookie\s*="], "storage")

# --- Crypto ---
_add("JS-CRYPTO-WEAK-HASH-001", "Weak cryptographic hash reference (MD5 / SHA-1)",
     "medium", "medium",
     "References to weak hash algorithms (MD5/SHA-1).",
     "Use modern hashes (SHA-256+) and current cryptographic guidance.",
     [r"\b(?:md5|sha1)\b"], "crypto")

_add("JS-CRYPTO-WEAK-CIPHER-001", "Weak cryptographic cipher/mode reference (DES / RC4 / AES-ECB)",
     "high", "medium",
     "References to weak/broken ciphers or modes (DES, RC4, AES-ECB).",
     "Use modern primitives and modes (e.g., AES-GCM) via Web Crypto or a well-reviewed library.",
     [r"\b(?:des|rc4|aes-?ecb|aes_ecb)\b"], "crypto")

_add("JS-RAND-001", "Math.random() used (not CSPRNG)",
     "low", "low",
     "Math.random is not cryptographically secure and must not be used for tokens, nonces, or keys.",
     "Use crypto.getRandomValues() or crypto.randomUUID().",
     [r"\bMath\.random\s*\("], "crypto")

# --- Hard-coded secrets (high-confidence patterns) ---
_add("JS-SECRET-PEM-001", "Private key / PEM block in source",
     "critical", "high",
     "Private key material embedded in client-side source.",
     "Remove immediately, rotate the key, and investigate how it reached the client.",
     [r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"], "secrets")

_add("JS-SECRET-AWS-001", "AWS access key pattern",
     "critical", "medium",
     "AWS access-key-id style token found in client code.",
     "Revoke the key in IAM, rotate, and remove from client bundles.",
     [r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"], "secrets")

_add("JS-SECRET-PROVIDER-001", "Provider / payment / Google API key pattern",
     "critical", "medium",
     "Cloud / payment provider key-like token found.",
     "Restrict by referrer / IP where possible, rotate, and keep secrets server-side.",
     [r"\bAIza[0-9A-Za-z\-_]{20,}\b",
      r"\bsk_live_[0-9a-zA-Z]{20,}\b",
      r"\bsk_test_[0-9a-zA-Z]{20,}\b",
      r"\bpk_live_[0-9a-zA-Z]{20,}\b",
      r"\bpk_test_[0-9a-zA-Z]{20,}\b"],
     "secrets")

_add("JS-SECRET-TOKEN-001", "Known high-value token shapes (GitHub / Slack / JWT)",
     "critical", "medium",
     "Bearer-style or service-specific token literal found.",
     "Revoke and rotate. Never ship long-lived tokens to the browser.",
     [r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
      r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
      r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"],
     "secrets")

_add("JS-SECRET-GENERIC-HIGH", "High-entropy secret-like assignment (heuristic)",
     "high", "low",
     "Variable with sensitive name assigned a high-entropy string literal.",
     "Confirm whether the value is a real secret. Move secrets server-side and rotate if exposed.",
     [],  # handled by generic scanner
     "secrets")

# --- Framework ---
_add("JS-REACT-001", "React dangerouslySetInnerHTML",
     "high", "high",
     "dangerouslySetInnerHTML bypasses React's XSS protections.",
     "Sanitize untrusted HTML (DOMPurify) or avoid the API. Test with DOM Invader.",
     [r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"], "framework")

_add("JS-ANGULAR-001", "Angular sanitizer bypass",
     "high", "high",
     "bypassSecurityTrust* disables Angular's built-in sanitization.",
     "Avoid bypass APIs for any untrusted input.",
     [r"bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\("], "framework")

_add("JS-VUE-001", "Vue v-html directive",
     "high", "medium",
     "v-html renders raw HTML and is an XSS sink.",
     "Avoid for untrusted data. Prefer text interpolation.",
     [r"\bv-html\s*=", r"\.directive\s*\(\s*['\"]html['\"]"], "framework")

# --- Open redirect ---
_add("JS-OPEN-REDIRECT-001", "Open redirect via location assignment from untrusted source",
     "high", "low",
     "location.* fed from search/hash/referrer can enable open redirects or XSS via javascript: URLs.",
     "Allowlist redirect targets. Never trust location.search / hash / referrer directly.",
     [r"location\.(?:href|assign|replace)\s*[=\(][^\n]{0,120}(?:location\.(?:search|hash)|URLSearchParams|document\.referrer)",
      r"window\.location\s*=\s*[^\n]{0,100}(?:search|hash|referrer)"],
     "redirect")

# --- SQL heuristic ---
_add("JS-SQL-001", "Possible SQL query built via concatenation / interpolation",
     "high", "low",
     "Potential SQL string construction passed to a DB query API (client-side or Node).",
     "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
     [
         r"\b(?:db|conn|connection|pool|client|sequelize|knex|trx|tx|entityManager|manager)\s*\.\s*(?:query|execute|raw)\s*\(\s*(['\"`])(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,220}?\1\s*\+",
         r"\b(?:db|conn|connection|pool|client|sequelize|knex|trx|tx|entityManager|manager)\s*\.\s*(?:query|execute|raw)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,260}\$\{",
         r"\b(?:mysql|mysql2|pg|mssql|oracledb|sqlite3)\b[\s\S]{0,120}\.\s*(?:query|execute)\s*\(\s*[A-Za-z_$][\w$]*\s*\+",
     ],
     "sqli")

# --- HTML ---
_add("HTML-EVENT-001", "Inline event handler attribute",
     "medium", "high",
     "Inline on* handlers are XSS sink points and complicate CSP.",
     "Move handlers to external JS via addEventListener. Enforce a strict CSP.",
     [r"\son(?:click|error|load|mouseover|focus|blur|submit|change|input|keyup|keydown|mouseenter|mouseleave)\s*=\s*['\"][^'\"]+['\"]",
      r"\son\w+\s*=\s*['\"][^'\"]*['\"]"],
     "html-xss")

_add("HTML-JS-URL-001", "javascript: URL in HTML attribute",
     "high", "high",
     "javascript: in href/src/action etc. can execute script.",
     "Block the javascript: scheme. Use proper event handlers for trusted actions only.",
     [r"(?:href|src|action|formaction|data)\s*=\s*['\"]?\s*javascript\s*:",
      r"['\"]javascript\s*:"],
     "html-xss")

_add("HTML-SCRIPT-SRC-HTTP-001", "Script loaded over HTTP",
     "high", "high",
     "HTTP script sources are vulnerable to MITM and trigger mixed-content warnings.",
     "Serve all scripts over HTTPS. Prefer SRI (integrity=) for third-party scripts.",
     [r"<script[^>]+src\s*=\s*['\"]http://"], "html")

_add("HTML-SCRIPT-INLINE-001", "Inline script block present",
     "low", "high",
     "Inline scripts enlarge XSS impact and make CSP harder.",
     "Move scripts to external files and use CSP nonces or hashes.",
     [r"<script(?![^>]*\bsrc\s*=)[^>]*>"], "html")

# ---------------------------------------------------------------------------
# Parsing / extraction helpers
# ---------------------------------------------------------------------------

_SCRIPT_BODY_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.I | re.S)
EVENT_HANDLER_RE = re.compile(r"\s(on[a-zA-Z][\w:-]*)\s*=\s*([\"'])(.*?)\2", re.I | re.S)
JS_URL_ATTR_RE = re.compile(r"\b(?:href|src|action|formaction)\s*=\s*([\"'])\s*javascript\s*:(.*?)\1", re.I | re.S)

def _line_number(text, idx):
    return text.count("\n", 0, idx) + 1

def _snippet(text, idx, radius=140):
    start = max(0, idx - radius)
    end = min(len(text), idx + radius)
    return text[start:end].replace("\n", "\\n").replace("\r", "")

def extract_inline_scripts(html):
    out = []
    if not html:
        return out
    for m in _SCRIPT_BODY_RE.finditer(html):
        attrs = m.group(1) or ""
        body = (m.group(2) or "").strip()
        if re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        if body:
            out.append({"code": body, "idx": m.start()})
    return out

def extract_event_handler_js(html):
    out = []
    if not html:
        return out
    for m in EVENT_HANDLER_RE.finditer(html):
        attr = (m.group(1) or "").lower()
        code = (m.group(3) or "").strip()
        if code:
            out.append({"name": attr, "code": code, "idx": m.start()})
    return out

def extract_javascript_url_payloads(html):
    out = []
    if not html:
        return out
    for m in JS_URL_ATTR_RE.finditer(html):
        code = (m.group(2) or "").strip()
        if code:
            out.append({"name": "javascript:", "code": code, "idx": m.start()})
    return out

def classify_content(url, content_type, body):
    kinds = set()
    u = (url or "").lower().split("?")[0]
    ct = (content_type or "").lower()

    if u.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
        kinds.add("js")
    if u.endswith((".html", ".htm", ".xhtml", ".shtml")):
        kinds.add("html")

    if "javascript" in ct or "ecmascript" in ct:
        kinds.add("js")
    if "html" in ct or "xhtml" in ct:
        kinds.add("html")

    if body:
        head = body[:600].lstrip().lower()
        if head.startswith("<!doctype html") or head.startswith("<html") or "<html" in head[:250]:
            kinds.add("html")
        if "<script" in body[:12000].lower():
            kinds.add("html")
        if head.startswith("(function") or head.startswith("!function") or head.startswith("\"use strict\""):
            kinds.add("js")
    return kinds

def analyze_text(text, rule_prefix_filter=None):
    findings = []
    if not text:
        return findings

    for rule in RULES:
        rid = rule["id"]
        if rule_prefix_filter == "html_only" and not rid.startswith("HTML-"):
            continue
        if rule_prefix_filter == "js_only" and rid.startswith("HTML-"):
            continue
        if not rule["patterns"]:
            continue

        count = 0
        for pat in rule["patterns"]:
            if count >= MAX_MATCHES_PER_RULE:
                break
            try:
                for m in pat.finditer(text):
                    if count >= MAX_MATCHES_PER_RULE:
                        break

                    # Suppress exact javascript:void(0)-style no-op URLs
                    # for JS-URL-JS-001 (optionally quoted / spaced / trailing ;)
                    # NOTE: m.group(0) is often just "javascript:", so inspect nearby text.
                    if rid in ("JS-URL-JS-001", "HTML-JS-URL-001"):
                        try:
                            tail = text[m.start(): m.start() + 240]
                        except Exception:
                            tail = ""

                        # Suppress common no-op javascript URLs:
                        # javascript:void(0), javascript:void(0);, javascript:;
                        if re.search(
                            r"javascript\s*:\s*(?:void\s*\(\s*0\s*\)\s*;?|;)(?:[\s'\"`>)\]]|$)",
                            tail,
                            re.I
                        ):
                            continue

                    findings.append({
                        "rule_id": rid,
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "detail": rule["detail"],
                        "fix": rule["fix"],
                        "category": rule["category"],
                        "line": _line_number(text, m.start()),
                        "match": m.group(0)[:220],
                        "snippet": _snippet(text, m.start())[:450],
                    })
                    count += 1
            except Exception:
                pass
    return findings

# ---------------------------------------------------------------------------
# Generic secret / token detector (analyst-oriented, minification-aware)
# ---------------------------------------------------------------------------

SENSITIVE_NAME_RE = re.compile(
    r"(secret|token|api[_-]?key|apikey|auth|authorization|bearer|passwd|password|session|"
    r"private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"hmac[_-]?key|aes[_-]?key|jwt|credential|signing[_-]?key|encryption[_-]?key|"
    r"app[_-]?key|app[_-]?secret|client[_-]?id|api[_-]?secret)",
    re.I
)
PLACEHOLDER_RE = re.compile(
    r"^(?:example|sample|test|demo|changeme|your[_-]?key|token[_-]?here|null|undefined|"
    r"insert[_-]?key|placeholder|xxx+|12345|abcdef|password|secret|todo|fixme|"
    r"lorem|ipsum|foo|bar|baz)$",
    re.I
)

ASSIGN_BIND_RE = re.compile(
    r"(?:(?:const|let|var)\s+)?(?:[A-Za-z_$][\w$]*\s*=\s*(?:new\s+[A-Za-z_$][\w$]*\s*(?:\([^)]*\))?|[^,;`'\"]+),)*"
    r"([A-Za-z_$][\w$]{0,80})\s*(?:=|:)\s*",
    re.M
)

def _extract_string_literal_at(text, pos):
    if pos >= len(text):
        return None, pos
    quote = text[pos]
    if quote not in ("'", '"', "`"):
        return None, pos
    i = pos + 1
    n = len(text)
    if quote in ("'", '"'):
        esc = False
        while i < n:
            ch = text[i]
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                return text[pos:i+1], i + 1
            elif ch == "\n" and quote != "`":
                break
            i += 1
        return None, pos

    depth = 1
    esc = False
    brace_depth = 0
    in_inner_sq = in_inner_dq = False
    while i < n:
        ch = text[i]
        if esc:
            esc = False
            i += 1
            continue
        if ch == "\\":
            esc = True
            i += 1
            continue
        if brace_depth > 0:
            if in_inner_sq:
                if ch == "'":
                    in_inner_sq = False
            elif in_inner_dq:
                if ch == '"':
                    in_inner_dq = False
            else:
                if ch == "'":
                    in_inner_sq = True
                elif ch == '"':
                    in_inner_dq = True
                elif ch == "`":
                    j = i + 1
                    nest_esc = False
                    nest_brace = 0
                    nest_sq = nest_dq = False
                    while j < n:
                        c2 = text[j]
                        if nest_esc:
                            nest_esc = False
                        elif c2 == "\\":
                            nest_esc = True
                        elif nest_brace > 0:
                            if nest_sq:
                                if c2 == "'":
                                    nest_sq = False
                            elif nest_dq:
                                if c2 == '"':
                                    nest_dq = False
                            else:
                                if c2 == "'":
                                    nest_sq = True
                                elif c2 == '"':
                                    nest_dq = True
                                elif c2 == "{":
                                    nest_brace += 1
                                elif c2 == "}":
                                    nest_brace -= 1
                                elif c2 == "`" and nest_brace == 0:
                                    break
                        else:
                            if c2 == "`":
                                break
                            if c2 == "$" and j + 1 < n and text[j+1] == "{":
                                nest_brace = 1
                                j += 1
                        j += 1
                    i = j
                elif ch == "{":
                    brace_depth += 1
                elif ch == "}":
                    brace_depth -= 1
            i += 1
            continue
        if ch == "`":
            return text[pos:i+1], i + 1
        if ch == "$" and i + 1 < n and text[i+1] == "{":
            brace_depth = 1
            i += 2
            continue
        i += 1
    return None, pos

def _iter_assignments(text):
    for m in ASSIGN_BIND_RE.finditer(text):
        name = m.group(1) or ""
        pos = m.end()
        lit, end = _extract_string_literal_at(text, pos)
        if lit:
            yield name, lit, m.start()

def _iter_bare_strings(text, min_len=12):
    i = 0
    n = len(text)
    while i < n:
        if text[i] in ("'", '"', "`"):
            lit, end = _extract_string_literal_at(text, i)
            if lit and len(lit) >= min_len + 2:
                yield lit, i
                i = end
                continue
        i += 1

CONST_STR_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{1,80})\s*=\s*"
    r"(['\"])([^'\"]{1,400})\2\s*;?",
    re.M
)
NON_STRING_RHS_RE = re.compile(
    r"^(?:async\s+)?(?:function\b|class\b|new\s+|"
    r"[A-Za-z_$][\w$]*\s*=>|\([^)]*\)\s*=>|\{|\[)", re.I
)
SIMPLE_STRING_EXPR_RE = re.compile(
    r"^(?:['\"][^'\"]*['\"]|`(?:\\.|[^`])*`|[A-Za-z_$][\w$]*)"
    r"(?:\s*\+\s*(?:['\"][^'\"]*['\"]|`(?:\\.|[^`])*`|[A-Za-z_$][\w$]*))*$",
    re.S
)

AUTH_SINK_RE = re.compile(
    r"(Authorization|Bearer|localStorage\.setItem|sessionStorage\.setItem|document\.cookie|"
    r"setRequestHeader\s*\(\s*['\"]Authorization|fetch\s*\(|axios\.|headers\s*\[|"
    r"\.setHeader\s*\(|XMLHttpRequest|btoa\s*\(|atob\s*\()",
    re.I
)

KNOWN_TOKEN_SHAPE_RE = re.compile(
    r"(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[0-9A-Za-z-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z\-_]{20,}|"
    r"sk_(?:live|test)_[0-9a-zA-Z]{20,}|"
    r"pk_(?:live|test)_[0-9a-zA-Z]{20,}|"
    r"rk_(?:live|test)_[0-9a-zA-Z]{20,}|"
    r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}|"
    r"xoxb-[0-9A-Za-z-]{10,}|xoxp-[0-9A-Za-z-]{10,}|"
    r"npm_[A-Za-z0-9]{30,}|"
    r"glpat-[A-Za-z0-9_\-]{20,}|"
    r"sk-[A-Za-z0-9]{20,}|"
    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*)"
)

HEX_RE = re.compile(r"^[A-Fa-f0-9]{24,}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{24,}={0,2}$")
SECRETISH_RE = re.compile(r"^[A-Za-z0-9@#$%^&*_+=\-.]{10,80}$")

NOISE_VALUE_RE = re.compile(
    r"(?:webpack|__esModule|function\s*\(|=>\s*\{|console\.|undefined|null|"
    r"application/json|text/html|Mozilla/|https?://|text/plain|image/|"
    r"multipart/|charset=|utf-8|xmlns|<!doctype|<html|<script|"
    r"Symbol\.for|react\.|strict_mode|forward_ref|suspense|profiler|"
    r"provider|context|memo|lazy|fragment|portal|client|server|"
    r"className|onClick|onChange|onSubmit|useState|useEffect|useRef|"
    r"jsx|jsxs|createElement|Object\.assign|Object\.freeze)",
    re.I
)

PATH_OR_ASSET_RE = re.compile(
    r"(?:"
    r"^[/\\.]|"
    r"[/\\]assets?[/\\]|"
    r"[/\\]static[/\\]|"
    r"[/\\]media[/\\]|"
    r"[/\\]images?[/\\]|"
    r"[/\\]css[/\\]|"
    r"[/\\]js[/\\]|"
    r"\.(?:png|jpe?g|gif|svg|webp|ico|css|js|mjs|map|woff2?|ttf|eot|json|html?)\b|"
    r"-[A-Za-z0-9_]{6,12}\.(?:png|jpe?g|gif|svg|webp|js|css|mjs)\b|"
    r"^data:image/"
    r")",
    re.I
)

CODE_FRAGMENT_RE = re.compile(
    r"(?:"
    r"^[\s\)\(\[\]\{\},;:=<>!&|?/\\+\-.*]+$|"
    r"Symbol\.for|"
    r"^[,;\)\]]|"
    r"[,{]\s*$|"
    r"strict_mode|"
    r"react\.[a-z_]+"
    r")",
    re.I
)

def _is_noise_value(s):
    if not s:
        return True
    s = s.strip()
    if len(s) < 8:
        return True
    if PLACEHOLDER_RE.match(s):
        return True
    if NOISE_VALUE_RE.search(s):
        return True
    if PATH_OR_ASSET_RE.search(s):
        return True
    if CODE_FRAGMENT_RE.search(s):
        return True
    if s.startswith("/") or s.startswith("./") or s.startswith("../"):
        return True
    if s.count("/") + s.count("\\") >= 2:
        return True
    return False

def _strip_quotes(s):
    if not s:
        return ""
    s = s.strip()
    if len(s) >= 2 and s[0] in ("'", '"', "`") and s[-1] == s[0]:
        return s[1:-1]
    return s

def _has_mixed_classes(s):
    has_l = any(c.islower() for c in s)
    has_u = any(c.isupper() for c in s)
    has_d = any(c.isdigit() for c in s)
    has_s = any((not c.isalnum()) for c in s)
    return ((1 if has_l else 0) + (1 if has_u else 0) + (1 if has_d else 0) + (1 if has_s else 0)) >= 3

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0.0) + 1.0
    ent = 0.0
    ln = float(len(s))
    for v in freq.values():
        p = v / ln
        ent -= p * math.log(p, 2)
    return ent

def _normalize_expr(expr):
    e = re.sub(r"//[^\n]*", "", expr)
    e = re.sub(r"/\*.*?\*/", "", e, flags=re.S)
    return e.strip()

def _extract_template_bodies(expr):
    out = []
    i = 0
    n = len(expr)
    while i < n:
        if expr[i] == "`":
            i += 1
            start = i
            esc = False
            while i < n:
                c = expr[i]
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == "`":
                    out.append(expr[start:i])
                    break
                i += 1
        i += 1
    return out

def _strip_template_interpolations(s):
    out = []
    i = 0
    n = len(s)
    while i < n:
        if i + 1 < n and s[i] == "$" and s[i + 1] == "{":
            i += 2
            depth = 1
            in_sq = in_dq = in_bt = esc = False
            while i < n and depth > 0:
                ch = s[i]
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif in_sq:
                    if ch == "'":
                        in_sq = False
                elif in_dq:
                    if ch == '"':
                        in_dq = False
                elif in_bt:
                    if ch == "`":
                        in_bt = False
                else:
                    if ch == "'":
                        in_sq = True
                    elif ch == '"':
                        in_dq = True
                    elif ch == "`":
                        in_bt = True
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                i += 1
        else:
            out.append(s[i])
            i += 1
    return "".join(out)

def _template_static_anchors(body):
    anchors = []
    i = 0
    n = len(body)
    buf = []
    while i < n:
        if i + 1 < n and body[i] == "$" and body[i + 1] == "{":
            if buf:
                anchors.append("".join(buf))
                buf = []
            i += 2
            depth = 1
            in_sq = in_dq = in_bt = esc = False
            while i < n and depth > 0:
                ch = body[i]
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif in_sq:
                    if ch == "'":
                        in_sq = False
                elif in_dq:
                    if ch == '"':
                        in_dq = False
                elif in_bt:
                    if ch == "`":
                        in_bt = False
                else:
                    if ch == "'":
                        in_sq = True
                    elif ch == '"':
                        in_dq = True
                    elif ch == "`":
                        in_bt = True
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                i += 1
        else:
            buf.append(body[i])
            i += 1
    if buf:
        anchors.append("".join(buf))
    return [a for a in anchors if a]

def _build_const_map(text):
    cmap = {}
    for m in CONST_STR_RE.finditer(text):
        name = m.group(1)
        val = m.group(3)
        if name and val:
            cmap[name] = val
    return cmap

def _resolve_simple_expr(expr, const_map):
    expr = _normalize_expr(expr)
    if not expr or NON_STRING_RHS_RE.match(expr):
        return "", False, False, []

    if expr.startswith("`"):
        bodies = _extract_template_bodies(expr)
        if not bodies:
            return "", False, False, []
        body = bodies[0]
        static = _strip_template_interpolations(body).strip()
        anchors = _template_static_anchors(body)
        return static, ("${" in body), True, anchors

    if expr.startswith("'") or expr.startswith('"'):
        return _strip_quotes(expr), False, True, [_strip_quotes(expr)]

    if not SIMPLE_STRING_EXPR_RE.match(expr):
        return "", False, False, []

    parts = [part.strip() for part in expr.split("+")]
    out = []
    dynamic = False
    for part in parts:
        if len(part) >= 2 and part[0] in ("'", '"') and part[-1] == part[0]:
            out.append(part[1:-1])
        elif part in const_map:
            out.append(const_map[part])
        else:
            dynamic = True
    joined = "".join(out).strip()
    return joined, dynamic, True, ([joined] if joined else [])

def _is_strong_anchor(a):
    a = (a or "").strip()
    if len(a) < 8:
        return False
    if _is_noise_value(a):
        return False
    if " " in a or "\t" in a:
        return False
    if a.endswith((".", "!", "?", ":")) and len(a) > 20:
        return False
    letter_ratio = sum(1 for c in a if c.isalpha()) / float(len(a))
    if letter_ratio > 0.85 and not any(c in a for c in "@#$%^&*_+=") and not any(c.isdigit() for c in a):
        return False
    if not _has_mixed_classes(a):
        return False
    has_special = any(c in a for c in "@#$%^&*_+=")
    ent = shannon_entropy(a)
    if has_special and ent >= 2.7 and len(a) >= 8:
        return True
    if len(a) >= 20 and ent >= 3.8 and letter_ratio < 0.9:
        return True
    if len(a) >= 12 and ent >= 3.5 and _has_mixed_classes(a) and any(c.isdigit() for c in a):
        return True
    return False

def _score_secret_candidate(name, compact, anchors, expr, dynamic, near_sink, has_sensitive_name):
    has_known_shape = (
        KNOWN_TOKEN_SHAPE_RE.search(expr or "") is not None
        or KNOWN_TOKEN_SHAPE_RE.search(compact or "") is not None
        or any(KNOWN_TOKEN_SHAPE_RE.search(a or "") for a in anchors)
    )

    strong_anchors = [a for a in anchors if _is_strong_anchor(a)]

    compact_ok = bool(compact) and not _is_noise_value(compact) and (" " not in compact)
    looks_like_prose = bool(compact) and (" " in compact or compact.endswith((".", "!", "?", ":")))

    score = 0
    reasons = []

    if has_sensitive_name:
        score += 3
        reasons.append("sensitive variable name")
    if has_known_shape:
        score += 8
        reasons.append("known token shape")
    if near_sink:
        score += 2
        reasons.append("auth/storage/network sink context")
    if strong_anchors:
        score += 4
        reasons.append("strong static anchors (%d)" % len(strong_anchors))
    if compact_ok and not looks_like_prose and len(compact) >= 16 and _has_mixed_classes(compact) and shannon_entropy(compact) >= 3.8:
        score += 2
        reasons.append("high-entropy mixed body")
    if compact_ok and not looks_like_prose and len(compact) >= 32 and shannon_entropy(compact) >= 4.0:
        score += 1
        reasons.append("long high-entropy body")
    if dynamic and strong_anchors:
        score += 3
        reasons.append("dynamic template with secret-like anchors")
    if dynamic and has_sensitive_name and not strong_anchors:
        score += 1
        reasons.append("dynamic composition")

    return score, reasons, has_known_shape, strong_anchors

def scan_generic_secrets(js_text):
    findings = []
    if not js_text:
        return findings

    const_map = _build_const_map(js_text)
    seen = set()

    for name, expr, start_idx in _iter_assignments(js_text):
        line = _line_number(js_text, start_idx)

        resolved, dynamic, eligible, anchors = _resolve_simple_expr(expr, const_map)
        compact = (resolved or "").strip()

        if not eligible:
            continue
        if compact and _is_noise_value(compact):
            continue
        if (not compact or len(compact) < 8) and not any(_is_strong_anchor(a) for a in anchors):
            continue

        has_sensitive_name = SENSITIVE_NAME_RE.search(name) is not None
        near_sink = AUTH_SINK_RE.search(
            js_text[start_idx:min(len(js_text), start_idx + 450)]
        ) is not None

        score, reasons, has_known_shape, strong_anchors = _score_secret_candidate(
            name, compact, anchors, expr, dynamic, near_sink, has_sensitive_name
        )

        if has_known_shape:
            min_score = 6
        elif has_sensitive_name and (strong_anchors or near_sink):
            min_score = 7
        elif strong_anchors and dynamic:
            min_score = 7
        else:
            min_score = 12

        if score < min_score:
            continue

        rid = "JS-SECRET-GEN-002" if dynamic else "JS-SECRET-GEN-001"
        # Analyst-tuned: generic secret findings should be high by default.
        sev = "high"
        conf = "low"
        if score >= 9:
            conf = "medium"
        if has_known_shape or score >= 12:
            sev = "critical"
            conf = "medium"
        if has_known_shape and (has_sensitive_name or strong_anchors):
            conf = "high"

        preview = compact[:48] if compact else (strong_anchors[0][:48] if strong_anchors else "")
        key = "%s|%s|%s|%s" % (rid, line, name, preview)
        if key in seen:
            continue
        seen.add(key)

        findings.append({
            "rule_id": rid,
            "title": "Secret/token candidate (%s)" % ("dynamic template" if dynamic else "static"),
            "severity": sev,
            "confidence": conf,
            "detail": (
                "Heuristic secret detection: %s. "
                "Static body length=%d entropy~=%.2f. Anchors=%s"
            ) % (
                ", ".join(reasons),
                len(compact),
                shannon_entropy(compact) if compact else 0.0,
                [a[:40] for a in strong_anchors] if strong_anchors else "[]",
            ),
            "fix": (
                "Treat as potentially live credential. Confirm, rotate if valid, "
                "remove from client-side bundles, move secret handling server-side."
            ),
            "category": "secrets",
            "line": line,
            "match": ("%s = %s" % (name, expr))[:240],
            "snippet": _snippet(js_text, start_idx)[:480],
        })

    for raw, start_idx in _iter_bare_strings(js_text, min_len=16):
        line = _line_number(js_text, start_idx)
        expr = raw
        resolved, dynamic, eligible, anchors = _resolve_simple_expr(expr, const_map)
        compact = (resolved or "").strip()

        if not eligible:
            continue
        if compact and _is_noise_value(compact):
            continue

        has_known_shape = (
            KNOWN_TOKEN_SHAPE_RE.search(compact or "") is not None
            or KNOWN_TOKEN_SHAPE_RE.search(expr or "") is not None
            or any(KNOWN_TOKEN_SHAPE_RE.search(a or "") for a in anchors)
        )
        if not has_known_shape:
            continue

        near_sink = AUTH_SINK_RE.search(
            js_text[max(0, start_idx - 80):min(len(js_text), start_idx + len(raw) + 120)]
        ) is not None

        score, reasons, has_known_shape, strong_anchors = _score_secret_candidate(
            "", compact, anchors, expr, dynamic, near_sink, False
        )
        if not has_known_shape:
            continue

        rid = "JS-SECRET-BARE-001"
        sev = "critical"
        conf = "medium"

        preview = compact[:48] if compact else raw[:40]
        key = "%s|%s|%s" % (rid, line, preview)
        if key in seen:
            continue
        seen.add(key)

        findings.append({
            "rule_id": rid,
            "title": "Bare secret/token-like literal (known shape)",
            "severity": sev,
            "confidence": conf,
            "detail": (
                "Known token shape in a string/template literal. Signals: %s. "
                "length=%d entropy~=%.2f"
            ) % (
                ", ".join(reasons) or "known shape",
                len(compact),
                shannon_entropy(compact) if compact else 0.0,
            ),
            "fix": (
                "Review whether this is a live credential or API key. "
                "If yes: rotate and remove from client code."
            ),
            "category": "secrets",
            "line": line,
            "match": raw[:240],
            "snippet": _snippet(js_text, start_idx)[:480],
        })

    return findings

# ---------------------------------------------------------------------------
# Source -> sink heuristic (improved window + more sinks)
# ---------------------------------------------------------------------------

SOURCE_RE = re.compile(
    r"(location\.(?:search|hash|href)|document\.(?:cookie|URL|referrer|baseURI)|"
    r"URLSearchParams\s*\(|window\.name|document\.location)",
    re.I
)
SINK_RE = re.compile(
    r"(innerHTML|outerHTML|insertAdjacentHTML|document\.write|srcdoc|"
    r"dangerouslySetInnerHTML|\.html\s*\(|eval\s*\(|new\s+Function|"
    r"setTimeout\s*\(\s*['\"`]|setInterval\s*\(\s*['\"`]|"
    r"location\.(?:href|assign|replace)|\.href\s*=|\.src\s*=)",
    re.I
)
SANITIZER_RE = re.compile(
    r"(DOMPurify\.sanitize|sanitizeHtml|trustedTypes|textContent\s*=|innerText\s*=)",
    re.I
)

def scan_source_sink_heuristic(js_text):
    findings = []
    if not js_text:
        return findings
    seen_lines = set()
    for sm in SOURCE_RE.finditer(js_text):
        sidx = sm.start()
        line = _line_number(js_text, sidx)
        if line in seen_lines:
            continue
        window = js_text[sidx:min(len(js_text), sidx + 450)]
        if SINK_RE.search(window) and not SANITIZER_RE.search(window):
            seen_lines.add(line)
            findings.append({
                "rule_id": "JS-TAINT-001",
                "title": "Potential source->sink DOM / code injection flow",
                "severity": "high",
                "confidence": "low",
                "detail": ("Possible flow from URL/cookie/referrer/window.name source into a "
                           "DOM HTML sink, location assignment, or dynamic code execution "
                           "without a visible sanitizer in the nearby window. "
                           "Manual confirmation required. Use Burp DOM Invader to test."),
                "fix": ("Sanitize or validate the source. Prefer safe DOM APIs (textContent). "
                          "For navigation sinks, allowlist destinations. "
                          "Reproduce with DOM Invader (Sources -> canary -> observe sinks)."),
                "category": "xss",
                "line": line,
                "match": window[:220],
                "snippet": _snippet(js_text, sidx)[:450],
            })
    return findings

# ---------------------------------------------------------------------------
# Context-aware analyzer (taint + sink gating) to reduce false positives
# ---------------------------------------------------------------------------

JS_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_$][\w$]{0,80})\s*=\s*([^;\n]{1,500})",
    re.M
)

JS_SOURCE_EXPR_RE = re.compile(
    r"(location\.(?:search|hash|href)|document\.(?:cookie|URL|referrer|baseURI)|"
    r"URLSearchParams\s*\(|window\.name|document\.location|"
    r"(?:local|session)Storage\s*\.\s*getItem\s*\(|"
    r"event\.data|message\.data)",
    re.I
)

JS_URL_SINK_RE = re.compile(
    r"(\.\s*(?:href|src|action)\s*=|"
    r"\blocation\.(?:href|assign|replace)\s*(?:=|\()|"
    r"\bwindow\.location\s*=|"
    r"\bsetAttribute\s*\(\s*['\"](?:href|src|action|formaction)['\"]\s*,)",
    re.I
)

JS_DANGEROUS_SCHEME_RE = re.compile(r"javascript\s*:", re.I)

HTML_JS_URL_ATTR_RE = re.compile(
    r"\b(?:href|src|action|formaction)\s*=\s*([\"'])(.*?)\1",
    re.I | re.S
)

JS_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_$][\w$]{0,80}\b")


class ContextualAnalyzer(object):
    def __init__(self, text, kind):
        self.text = text or ""
        self.kind = kind  # "js" or "html"
        self.lines = self.text.splitlines()
        self.tainted = set()
        self.assignments = []   # list of dict: {name, expr, idx, line}
        self.url_sinks = []     # list of dict: {expr, idx, line, raw}
        self._build_state()

    def _line(self, idx):
        return _line_number(self.text, max(0, idx))

    def _build_state(self):
        if self.kind != "js" or not self.text:
            return

        # 1) collect assignments
        for m in JS_ASSIGN_RE.finditer(self.text):
            name = m.group(1) or ""
            expr = (m.group(2) or "").strip()
            self.assignments.append({
                "name": name,
                "expr": expr,
                "idx": m.start(),
                "line": self._line(m.start()),
            })

        # 2) seed taint from direct source expressions
        changed = True
        for a in self.assignments:
            if JS_SOURCE_EXPR_RE.search(a["expr"]):
                self.tainted.add(a["name"])

        # 3) iterate propagation through identifiers
        # lightweight fixed-point
        max_rounds = 6
        rounds = 0
        while changed and rounds < max_rounds:
            changed = False
            rounds += 1
            for a in self.assignments:
                if a["name"] in self.tainted:
                    continue
                ids = set(JS_IDENTIFIER_RE.findall(a["expr"] or ""))
                if ids.intersection(self.tainted):
                    self.tainted.add(a["name"])
                    changed = True

        # 4) collect URL-like sinks with RHS expression window
        for m in JS_URL_SINK_RE.finditer(self.text):
            idx = m.start()
            line = self._line(idx)
            window = self.text[idx:min(len(self.text), idx + 420)]

            # heuristic extraction of RHS for "= ..." or arg for setAttribute
            expr = window
            eq_pos = window.find("=")
            if eq_pos != -1:
                expr = window[eq_pos + 1:eq_pos + 220]
            elif "setAttribute" in window:
                comma = window.find(",")
                if comma != -1:
                    expr = window[comma + 1:comma + 220]

            self.url_sinks.append({
                "expr": expr.strip(),
                "idx": idx,
                "line": line,
                "raw": window[:260],
            })

    def _expr_is_tainted(self, expr):
        if not expr:
            return False
        if JS_SOURCE_EXPR_RE.search(expr):
            return True
        ids = set(JS_IDENTIFIER_RE.findall(expr))
        if ids.intersection(self.tainted):
            return True
        return False

    def _find_nearby_url_sink(self, line, radius=4):
        for s in self.url_sinks:
            if abs((s.get("line") or 0) - (line or 0)) <= radius:
                return s
        return None

    def validate(self, finding):
        rid = finding.get("rule_id", "")
        line = finding.get("line", 0)
        match = finding.get("match", "") or ""
        snippet = finding.get("snippet", "") or ""

        # --- JS-URL-JS-001 ---
        if rid == "JS-URL-JS-001":
            if self.kind != "js":
                return None

            sink = self._find_nearby_url_sink(line, radius=5)

            # If not tied to actual navigation/resource sink -> suppress
            if not sink:
                return None

            expr = (sink.get("expr") or "") + " " + match + " " + snippet
            tainted = self._expr_is_tainted(expr)

            # static javascript:void(0) etc. without taint => informational hygiene
            if not tainted:
                lowered = expr.lower()
                if "javascript:void(0" in lowered or "javascript:;" in lowered:
                    finding["severity"] = "info"
                    finding["confidence"] = "medium"
                    finding["detail"] = (
                        "javascript: scheme assigned to URL sink, but no user-controlled "
                        "data flow detected nearby. Treat as hygiene/CSP concern unless "
                        "runtime data binding changes this."
                    )
                    return finding
                return None

            finding["severity"] = "high"
            finding["confidence"] = "high"
            finding["detail"] = (
                "Potential user-controlled flow into javascript: URL sink. "
                "Source/propagation evidence suggests attacker influence. "
                "Validate exploitability with DOM Invader."
            )
            return finding

        # --- HTML-JS-URL-001 ---
        if rid == "HTML-JS-URL-001":
            if self.kind != "html":
                return finding

            blob = (match + " " + snippet).lower()

            # Suppress common no-op javascript anchors
            if re.search(r"javascript\s*:\s*(?:void\s*\(\s*0\s*\)\s*;?|;)\b", blob, re.I):
                return None

            # Determine if this is likely static attribute vs dynamic tainted composition
            # For raw HTML response scanning, mostly static; downgrade unless dynamic markers
            blob = (match + " " + snippet).lower()
            dynamic_markers = ("${", "{{", "<%=", "concat(", "+")
            has_dynamic_marker = any(dm in blob for dm in dynamic_markers)

            if has_dynamic_marker:
                finding["severity"] = "medium"
                finding["confidence"] = "medium"
                finding["detail"] = (
                    "javascript: URL found with dynamic composition markers. "
                    "Potentially exploitable if attacker controls injected segment."
                )
                return finding

            # Static literal in HTML should be low/info, not high vulnerability by default
            finding["severity"] = "low"
            finding["confidence"] = "high"
            finding["detail"] = (
                "Static javascript: URL attribute found. Usually a security hygiene / CSP "
                "issue unless user-controlled data can influence the attribute at runtime."
            )
            return finding

        # --- JS-DOM-XSS-004 (href/src/action/location assignments) ---
        if rid == "JS-DOM-XSS-004":
            if self.kind != "js":
                return None
            sink = self._find_nearby_url_sink(line, radius=5)
            if not sink:
                return None
            expr = (sink.get("expr") or "") + " " + snippet
            tainted = self._expr_is_tainted(expr)

            if not tainted:
                # keep as weaker signal, not medium-by-default
                finding["severity"] = "low"
                finding["confidence"] = "low"
                finding["detail"] = (
                    "URL/resource sink assignment found without clear user-controlled source "
                    "flow in local context."
                )
                return finding

            finding["severity"] = "medium"
            finding["confidence"] = "medium"
            finding["detail"] = (
                "Potential user-controlled flow into navigation/resource sink. "
                "Validate allowlisting and scheme restrictions."
            )
            return finding

        # default: keep existing finding
        return finding

    def run(self, findings):
        out = []
        for f in findings or []:
            try:
                vf = self.validate(dict(f))
                if vf is not None:
                    out.append(vf)
            except Exception:
                # fail-open for non-target rules
                out.append(f)
        return out


# ---------------------------------------------------------------------------
# SQL false-positive gate
# ---------------------------------------------------------------------------

SQL_KEYWORD_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|VALUES|SET)\b", re.I)
SQL_DBAPI_RE = re.compile(r"\b(?:query|execute|raw)\s*\(", re.I)
SQL_NOISE_RE = re.compile(
    r"(?:\"use strict\";var|/\*!|@license|drupal|webpackJsonp|__esModule|function\s*\()",
    re.I
)

def _sql_finding_is_valid(f):
    if f.get("rule_id") != "JS-SQL-001":
        return True
    blob = (f.get("match", "") or "") + " " + (f.get("snippet", "") or "")
    if SQL_NOISE_RE.search(blob):
        return False
    if not SQL_KEYWORD_RE.search(blob):
        return False
    if not SQL_DBAPI_RE.search(blob):
        return False
    return True

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

class ScanCache(object):
    def __init__(self, max_items=8000, ttl_seconds=7200):
        self.max_items = max_items
        self.ttl = ttl_seconds
        self.store = OrderedDict()

    def _evict(self):
        now = time.time()
        dead = []
        for k, ts in self.store.items():
            if now - ts > self.ttl:
                dead.append(k)
        for k in dead:
            self.store.pop(k, None)
        while len(self.store) > self.max_items:
            self.store.popitem(last=False)

    def seen(self, key):
        self._evict()
        if key in self.store:
            ts = self.store.pop(key)
            self.store[key] = ts
            return True
        return False

    def mark(self, key):
        self._evict()
        if key in self.store:
            self.store.pop(key, None)
        self.store[key] = time.time()

def _sha256_text(s):
    if s is None:
        b = "".encode("utf-8")
    else:
        try:
            if isinstance(s, unicode):
                b = s.encode("utf-8", "ignore")
            else:
                try:
                    b = s.decode("utf-8", "ignore").encode("utf-8")
                except Exception:
                    b = unicode(s).encode("utf-8", "ignore")
        except Exception:
            try:
                b = ("" + s).encode("utf-8", "ignore")
            except Exception:
                b = repr(s).encode("utf-8", "ignore")
    return hashlib.sha256(b).hexdigest()

# ---------------------------------------------------------------------------
# Optional Semgrep bridge - robust Windows path / executable checks
# ---------------------------------------------------------------------------

def _is_file(path):
    if not path:
        return False
    try:
        return File(path).isFile()
    except Exception:
        return False

def _is_windows_apps_stub(path):
    if not path:
        return False
    p = path.replace("/", "\\").lower()
    return "\\windowsapps\\" in p and p.endswith("python3.exe")

def _probe_python(py3_path):
    if not py3_path or not py3_path.strip():
        return False, "Python 3 path is empty"

    path = py3_path.strip()

    if _is_windows_apps_stub(path):
        return False, (
            "This is the Microsoft Store App Execution Alias "
            "(WindowsApps\\python3.exe), not a real Python install. "
            "Install Python from https://www.python.org/downloads/ "
            "(check 'Add python.exe to PATH') or use the full path to a "
            "real python.exe, e.g. "
            "C:\\Users\\<you>\\AppData\\Local\\Programs\\Python\\Python3x\\python.exe "
            "or the 'py' launcher."
        )

    try:
        p = subprocess.Popen(
            [path, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = p.communicate()
        combined = ((out or "") + (err or "")).strip()
        if p.returncode == 0 and combined:
            return True, "Python OK: %s" % combined[:80]
        return False, "python --version failed (rc=%s): %s" % (
            p.returncode, combined[:300] or "<no output>")
    except Exception as ex:
        if not _is_file(path):
            return False, (
                "Python 3 executable not found or not runnable: %s "
                "(Java File.isFile=False; also failed to execute: %s). "
                "Use a full path to a real python.exe from python.org, "
                "not the WindowsApps stub."
            ) % (path, ex)
        return False, "Failed to execute Python at %s: %s" % (path, ex)

def check_semgrep_bridge(py3_path, bridge_script):
    status = {"ok": False, "message": "Not tested", "details": {}}

    py_ok, py_msg = _probe_python(py3_path)
    if not py_ok:
        status["message"] = py_msg
        return status

    if not bridge_script or not bridge_script.strip():
        status["message"] = "Bridge script path is empty"
        return status
    bridge_script = bridge_script.strip()
    if not _is_file(bridge_script):
        try:
            f = open(bridge_script, "rb")
            f.close()
        except Exception:
            status["message"] = (
                "Bridge script not found or not readable: %s. "
                "Use the full absolute path to semgrep_bridge.py."
            ) % bridge_script
            return status

    try:
        p = subprocess.Popen(
            [py3_path.strip(), bridge_script, "--health-check"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = p.communicate()
        if not out:
            status["message"] = "Bridge returned no JSON. stderr=%s" % ((err or "")[:500])
            return status
        data = json.loads(out)
        status["details"] = data

        core_ok = bool(
            data.get("bridge_ok") is True
            and data.get("semgrep_available") is True
            and data.get("json_ok") is True
            and data.get("local_rule_ok") is True
        )
        finding_verified = data.get("expected_finding_ok") is True
        results = data.get("results") or []
        has_health_result = False
        for r in results:
            msg = (r.get("extra") or {}).get("message") or r.get("message") or ""
            cid = r.get("check_id") or ""
            if "health" in msg.lower() or "health" in cid.lower() or "eval" in cid.lower():
                has_health_result = True
                break

        status["ok"] = core_ok and (finding_verified or has_health_result or data.get("ok") is True)

        if status["ok"]:
            note = "finding verified" if finding_verified else "Semgrep operational (finding-format soft-pass)"
            status["message"] = "Healthy: Semgrep %s via %s; %s. (%s)" % (
                data.get("semgrep_version", "unknown"),
                data.get("semgrep_runner", "unknown"),
                note,
                py_msg)
        else:
            status["message"] = "Unhealthy: %s" % (data.get("error") or "health test failed")
    except Exception as ex:
        status["message"] = "Bridge health check failed: %s" % ex
    return status

def run_semgrep_bridge(py3_path, bridge_script, js_code, packs, timeout_sec=45):
    findings = []
    if not py3_path or not bridge_script or not js_code or not packs:
        return findings

    py_ok, _ = _probe_python(py3_path)
    if not py_ok:
        return findings
    if not _is_file(bridge_script):
        try:
            f = open(bridge_script, "rb")
            f.close()
        except Exception:
            return findings

    tf = None
    tf_path = None
    p = None
    try:
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".js")
        tf_path = tf.name
        if isinstance(js_code, unicode):
            tf.write(js_code.encode("utf-8"))
        else:
            tf.write(js_code)
        tf.close()
        tf = None

        cmd = [py3_path.strip(), bridge_script.strip(), "--target", tf_path, "--packs", ",".join(packs)]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        deadline = time.time() + max(5, int(timeout_sec))
        while p.poll() is None:
            if time.time() >= deadline:
                try:
                    p.destroy()
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
                return findings
            time.sleep(0.15)

        out, err = p.communicate()

        if not out:
            return findings

        data = json.loads(out)
        for r in data.get("results", []):
            line = (((r.get("start") or {}).get("line")) or 1)
            msg = r.get("message") or "Semgrep finding"
            rule_id = r.get("check_id") or "UNKNOWN"
            sev = (r.get("extra", {}).get("severity") or "WARNING").lower()

            if sev in ("error", "critical"):
                s = "high"
            elif sev == "warning":
                s = "medium"
            else:
                s = "low"

            lines = (r.get("extra", {}).get("lines") or "")
            findings.append({
                "rule_id": "SEMGREP-" + rule_id,
                "title": "[Semgrep] " + msg,
                "severity": s,
                "confidence": "medium",
                "detail": "Semgrep matched rule '%s'." % rule_id,
                "fix": "Review the rule guidance and remediate the unsafe pattern / dataflow.",
                "category": "semgrep",
                "line": int(line),
                "match": lines[:220],
                "snippet": lines[:450],
            })
    except Exception:
        pass
    finally:
        try:
            if p is not None and p.poll() is None:
                try:
                    p.destroy()
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            if tf is not None:
                tf.close()
            if tf_path:
                f = File(tf_path)
                if f.exists():
                    f.delete()
        except Exception:
            pass

    return findings

# ---------------------------------------------------------------------------
# Issue wrapper - richer analyst detail + DOM Invader hints
# ---------------------------------------------------------------------------

class JsAuditIssue(IScanIssue):
    def __init__(self, helpers, baseRequestResponse, httpService, url, finding):
        self._helpers = helpers
        self._base = baseRequestResponse
        self._httpService = httpService
        self._url = url
        self._f = finding
        self._sev = SEV_TO_BURP.get(finding["severity"], BURP_MEDIUM)

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "[JS-Audit] %s" % self._f["title"]

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return self._sev

    def getConfidence(self):
        c = self._f.get("confidence", "medium")
        if c == "high":
            return "Certain"
        if c == "low":
            return "Tentative"
        return "Firm"

    def getIssueBackground(self):
        return (
            "Reported by Defensive JS Audit (heuristic JS/HTML checks + optional Semgrep bridge). "
            "Findings are indicators that require manual validation by a vulnerability analyst. "
            "For DOM XSS / source->sink issues, use Burp's DOM Invader (Browser -> DOM Invader) "
            "to inject canaries into sources and observe sinks."
        )

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        f = self._f
        extra = ""
        cat = f.get("category", "")
        if cat in ("xss", "html-xss", "framework") or "TAINT" in f.get("rule_id", ""):
            extra = (
                "<br/><b>Analyst tip (DOM Invader)</b>: Open the page in Burp Browser, "
                "enable DOM Invader, inject a canary into the relevant source "
                "(location.search / hash / referrer / postMessage / etc.), and watch for "
                "the canary reaching the reported sink. Confirm exploitability before reporting."
            )
        if cat == "secrets":
            extra = (
                "<br/><b>Analyst tip</b>: Treat as potentially live. Verify the value is not a "
                "placeholder, check whether it is still valid (carefully), and ensure it is "
                "rotated and removed from all client-side bundles."
            )
        return "".join([
            "<b>Rule</b>: %s<br/>" % _esc(f["rule_id"]),
            "<b>Category</b>: %s<br/>" % _esc(f["category"]),
            "<b>Severity (engine)</b>: %s<br/>" % _esc(f["severity"]),
            "<b>Approx. line</b>: %s<br/>" % f["line"],
            "<b>Match</b>: <code>%s</code><br/><br/>" % _esc(f["match"]),
            "<b>Detail</b>: %s<br/><br/>" % _esc(f["detail"]),
            "<b>Snippet</b>:<br/><pre>%s</pre>" % _esc(f["snippet"]),
            extra,
        ])

    def getRemediationDetail(self):
        return _esc(self._f.get("fix") or "")

    def getHttpMessages(self):
        return [self._base]

    def getHttpService(self):
        return self._httpService

def _safe_text(s):
    if s is None:
        return u""
    try:
        if isinstance(s, unicode):
            u = s
        else:
            try:
                u = s.decode("utf-8", "replace")
            except Exception:
                try:
                    u = unicode(s)
                except Exception:
                    u = unicode(str(s), "utf-8", "replace")
    except Exception:
        try:
            u = unicode(repr(s), "utf-8", "replace")
        except Exception:
            u = u""
    return u.replace(u"\x00", u"")

def _esc(s):
    if s is None:
        return u""
    s = _safe_text(s)
    return (s.replace(u"&", u"&amp;")
             .replace(u"<", u"&lt;")
             .replace(u">", u"&gt;")
             .replace(u'"', u"&quot;"))

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

class SeverityPanel(JPanel):
    DOM_INVADER_TEST_GUIDE = (
        "DOM Invader quick workflow:\n"
        "1) Open target in Burp Browser and enable DOM Invader.\n"
        "2) Inject canary into likely sources:\n"
        "   - ?q=burpcanary123\n"
        "   - #burpcanary123\n"
        "   - postMessage('burpcanary123', '*') from a controlled origin\n"
        "3) Observe if canary reaches sinks:\n"
        "   - innerHTML / outerHTML / insertAdjacentHTML / document.write\n"
        "   - eval / Function / setTimeout(string)\n"
        "   - location.href / srcdoc / jQuery html/append\n"
        "4) Try exploit primitives only after canary flow is confirmed.\n"
        "5) Report with source, sink, transform, and exploitability constraints."
    )

    def __init__(self, extender):
        JPanel.__init__(self)
        self.extender = extender
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))

        title = JLabel("Defensive JS Audit - Hybrid (Analyst Edition)")
        title.setFont(Font("SansSerif", Font.BOLD, 14))
        self.add(title)

        self.add(JLabel("Report severities:"))
        self.cb_critical = JCheckBox("Critical", True)
        self.cb_high = JCheckBox("High", True)
        self.cb_medium = JCheckBox("Medium", True)
        self.cb_low = JCheckBox("Low", False)
        self.cb_info = JCheckBox("Info", False)

        for cb in (self.cb_critical, self.cb_high, self.cb_medium, self.cb_low, self.cb_info):
            self.add(cb)

        self.add(JLabel(" "))
        self.cb_passive = JCheckBox("Enable automatic response scanning", True)
        self.cb_in_scope_only = JCheckBox("Automatic scans: Burp scope only", True)
        self.cb_tool_proxy = JCheckBox("Capture Proxy responses", True)
        self.cb_tool_repeater = JCheckBox("Capture Repeater responses", True)
        self.cb_tool_scanner = JCheckBox("Capture Scanner responses", True)
        self.cb_tool_intruder = JCheckBox("Capture Intruder responses", False)
        self.cb_tool_extensions = JCheckBox("Capture extension-generated responses", False)
        self.cb_scan_js = JCheckBox("Scan JavaScript responses / extracted JS fragments", True)
        self.cb_scan_html = JCheckBox("Scan HTML markup rules", True)
        self.cb_scan_taint = JCheckBox("Enable source->sink heuristic", True)

        self.add(self.cb_passive)
        self.add(self.cb_in_scope_only)
        self.add(self.cb_tool_proxy)
        self.add(self.cb_tool_repeater)
        self.add(self.cb_tool_scanner)
        self.add(self.cb_tool_intruder)
        self.add(self.cb_tool_extensions)
        self.add(self.cb_scan_js)
        self.add(self.cb_scan_html)
        self.add(self.cb_scan_taint)

        self.add(JLabel(" "))
        self.cb_semgrep = JCheckBox("Enable Semgrep bridge (optional)", False)
        self.add(self.cb_semgrep)
        self.cb_semgrep_passive = JCheckBox("Run Semgrep on automatic/passive captures (slow)", False)
        self.add(self.cb_semgrep_passive)

        self.add(JLabel("Python3 path (for Semgrep bridge):"))
        self.txt_py3 = JTextField(60)
        self.add(self.txt_py3)

        self.add(JLabel("semgrep_bridge.py path:"))
        self.txt_bridge = JTextField(60)
        self.add(self.txt_bridge)

        self.add(JLabel("Semgrep timeout seconds (default 45):"))
        self.txt_semgrep_timeout = JTextField("45")
        self.add(self.txt_semgrep_timeout)

        self.add(JLabel("Max parallel Semgrep jobs (1-4, default 1):"))
        self.txt_semgrep_threads = JTextField("1")
        self.add(self.txt_semgrep_threads)

        self.add(JLabel("Semgrep packs:"))
        self.cb_pack_domxss = JCheckBox("domxss", True)
        self.cb_pack_secrets = JCheckBox("secrets", True)
        self.cb_pack_crypto = JCheckBox("crypto", False)
        self.add(self.cb_pack_domxss)
        self.add(self.cb_pack_secrets)
        self.add(self.cb_pack_crypto)

        semgrep_row = JPanel()
        self.btn_test_semgrep = JButton("Test Semgrep bridge")
        self.lbl_semgrep_status = JLabel("Not tested")
        semgrep_row.add(self.btn_test_semgrep)
        semgrep_row.add(self.lbl_semgrep_status)
        self.add(semgrep_row)

        self.add(JLabel(" "))
        helper_row = JPanel()
        self.btn_copy_dom_invader = JButton("Copy DOM Invader test checklist")
        helper_row.add(self.btn_copy_dom_invader)
        self.add(helper_row)

        self.add(JLabel(" "))
        btn_row = JPanel()
        btn_all = JButton("Select all severities")
        btn_def = JButton("Defaults (Crit+High+Med)")
        btn_row.add(btn_all)
        btn_row.add(btn_def)
        self.add(btn_row)

        self.add(JLabel(" "))
        self.log = JTextArea(12, 80)
        self.log.setEditable(False)
        self.log.setLineWrap(True)
        self.add(JScrollPane(self.log))

        def wire():
            class AllAL(ActionListener):
                def actionPerformed(self2, e):
                    for cb in (self.cb_critical, self.cb_high, self.cb_medium, self.cb_low, self.cb_info):
                        cb.setSelected(True)

            class DefAL(ActionListener):
                def actionPerformed(self2, e):
                    self.cb_critical.setSelected(True)
                    self.cb_high.setSelected(True)
                    self.cb_medium.setSelected(True)
                    self.cb_low.setSelected(False)
                    self.cb_info.setSelected(False)

            class TestSemgrepAL(ActionListener):
                def actionPerformed(self2, e):
                    self.lbl_semgrep_status.setText("Testing...")
                    self.btn_test_semgrep.setEnabled(False)
                    py3 = self.txt_py3.getText().strip()
                    bridge = self.txt_bridge.getText().strip()
                    def _worker():
                        try:
                            status = check_semgrep_bridge(py3, bridge)
                        except Exception as ex:
                            status = {"ok": False, "message": "Test failed: %s" % ex}
                        def _done():
                            self.lbl_semgrep_status.setText("Healthy" if status.get("ok") else "Unhealthy")
                            self.append_log(status.get("message", "Unknown bridge status"))
                            self.btn_test_semgrep.setEnabled(True)
                        SwingUtilities.invokeLater(_done)
                    from threading import Thread
                    Thread(target=_worker).start()

            class CopyDomInvaderAL(ActionListener):
                def actionPerformed(self2, e):
                    try:
                        sel = StringSelection(self.DOM_INVADER_TEST_GUIDE)
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, None)
                        self.append_log("DOM Invader checklist copied to clipboard.")
                    except Exception as ex:
                        self.append_log("Clipboard copy failed: %s" % ex)

            btn_all.addActionListener(AllAL())
            btn_def.addActionListener(DefAL())
            self.btn_test_semgrep.addActionListener(TestSemgrepAL())
            self.btn_copy_dom_invader.addActionListener(CopyDomInvaderAL())

        SwingUtilities.invokeLater(wire)

    def allowed_severities(self):
        s = set()
        if self.cb_critical.isSelected():
            s.add("critical")
        if self.cb_high.isSelected():
            s.add("high")
        if self.cb_medium.isSelected():
            s.add("medium")
        if self.cb_low.isSelected():
            s.add("low")
        if self.cb_info.isSelected():
            s.add("info")
        return s

    def passive_enabled(self):
        return self.cb_passive.isSelected()

    def in_scope_only(self):
        return self.cb_in_scope_only.isSelected()

    def tool_enabled(self, tool_flag):
        try:
            mapping = {
                self.extender._callbacks.TOOL_PROXY: self.cb_tool_proxy,
                self.extender._callbacks.TOOL_REPEATER: self.cb_tool_repeater,
                self.extender._callbacks.TOOL_SCANNER: self.cb_tool_scanner,
                self.extender._callbacks.TOOL_INTRUDER: self.cb_tool_intruder,
                self.extender._callbacks.TOOL_EXTENDER: self.cb_tool_extensions,
            }
            cb = mapping.get(tool_flag)
            return cb is not None and cb.isSelected()
        except Exception:
            return False

    def scan_js_enabled(self):
        return self.cb_scan_js.isSelected()

    def scan_html_enabled(self):
        return self.cb_scan_html.isSelected()

    def scan_taint_enabled(self):
        return self.cb_scan_taint.isSelected()

    def semgrep_enabled(self):
        return self.cb_semgrep.isSelected()

    def semgrep_on_passive(self):
        return self.cb_semgrep.isSelected() and self.cb_semgrep_passive.isSelected()

    def semgrep_timeout(self):
        try:
            return max(5, int(self.txt_semgrep_timeout.getText().strip() or "45"))
        except Exception:
            return 45

    def semgrep_max_threads(self):
        try:
            n = int(self.txt_semgrep_threads.getText().strip() or "1")
            return max(1, min(4, n))
        except Exception:
            return 1

    def semgrep_packs(self):
        packs = []
        if self.cb_pack_domxss.isSelected():
            packs.append("domxss")
        if self.cb_pack_secrets.isSelected():
            packs.append("secrets")
        if self.cb_pack_crypto.isSelected():
            packs.append("crypto")
        return packs

    def append_log(self, msg):
        try:
            msg = _safe_text(msg)
        except Exception:
            msg = u"%s" % (msg,)
        def _do():
            try:
                self.log.append(msg + u"\n")
                self.log.setCaretPosition(self.log.getDocument().getLength())
            except Exception:
                pass
        SwingUtilities.invokeLater(_do)

# ---------------------------------------------------------------------------
# Context menu action
# ---------------------------------------------------------------------------

class MenuAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, e):
        msgs = self.invocation.getSelectedMessages()
        if msgs is None or len(msgs) == 0:
            return
        for message in msgs:
            self.extender.scan_message(message, manual=True)

# ---------------------------------------------------------------------------
# Main extender
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IScannerCheck, ITab, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName(EXTENSION_NAME)

        self.ui = SeverityPanel(self)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        try:
            callbacks.registerScannerCheck(self)
        except Exception:
            pass

        self._scan_cache = ScanCache(max_items=8000, ttl_seconds=7200)
        self._capture_count = 0
        self._scope_skip_count = 0
        self._tool_skip_count = 0
        self._semgrep_inflight = 0
        self._semgrep_queue = []
        self._semgrep_lock = __import__("threading").Lock()

        self._stdout.println("[%s] loaded - %d rules" % (EXTENSION_NAME, len(RULES)))
        self.ui.append_log("Loaded. Windows-safe path checks enabled. Cache + DOM Invader guidance active.")
        self.ui.append_log("In-scope filtering fix active: callbacks.isInScope(URL)")

    def getTabCaption(self):
        return "JS Audit"

    def getUiComponent(self):
        return self.ui

    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("Defensive JS Audit - scan response")
        item.addActionListener(MenuAction(self, invocation))
        menu.add(item)
        return menu

    def _is_in_scope(self, messageInfo):
        """
        Fixed scope handling:
        - extracts URL from request
        - uses callbacks.isInScope(URL)
        - safe fallback behavior on malformed messages
        """
        try:
            req_info = self._helpers.analyzeRequest(messageInfo)
            if req_info is None:
                return False
            url = req_info.getUrl()
            if url is None:
                return False
            return bool(self._callbacks.isInScope(url))
        except Exception as ex:
            self._stderr.println("[JS-Audit] scope check error: %s" % ex)
            return False

    def _body_text(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()
        if response is None:
            return None, None, None
        analyzed = self._helpers.analyzeResponse(response)
        body_offset = analyzed.getBodyOffset()
        body_bytes = response[body_offset:]
        if body_bytes is None or len(body_bytes) == 0:
            return None, analyzed, ""
        if len(body_bytes) > MAX_BODY_BYTES:
            return None, analyzed, None
        try:
            text = self._helpers.bytesToString(body_bytes)
        except Exception:
            try:
                text = "".join(chr(b & 0xff) for b in body_bytes)
            except Exception:
                return None, analyzed, ""
        return text, analyzed, text

    def _scan_key(self, url_str, mode, text, semgrep_on, packs_csv, taint_on):
        base_url = (url_str or "").split("#")[0].split("?", 1)[0]
        h = _sha256_text(text)
        return "%s|%s|%s|sg=%s|packs=%s|taint=%s" % (
            base_url, mode, h, "1" if semgrep_on else "0", packs_csv, "1" if taint_on else "0")

    def _message_dedup_key(self, baseRequestResponse, url_str, body_text=None):
        try:
            base_url = (url_str or "").split("#")[0].split("?", 1)[0]
            if body_text is not None:
                return "msg|%s|%s" % (base_url, _sha256_text(body_text))
            response = baseRequestResponse.getResponse()
            if response is None:
                return None
            analyzed = self._helpers.analyzeResponse(response)
            body_offset = analyzed.getBodyOffset()
            body_bytes = response[body_offset:]
            try:
                text = self._helpers.bytesToString(body_bytes) if body_bytes is not None else ""
            except Exception:
                text = str(len(body_bytes) if body_bytes is not None else 0)
            return "msg|%s|%s" % (base_url, _sha256_text(text))
        except Exception:
            return None

    def _semgrep_pump(self):
        from threading import Thread
        while True:
            job = None
            with self._semgrep_lock:
                max_n = 1
                try:
                    max_n = self.ui.semgrep_max_threads()
                except Exception:
                    max_n = 1
                if self._semgrep_inflight >= max_n:
                    return
                if not self._semgrep_queue:
                    return
                job = self._semgrep_queue.pop(0)
                self._semgrep_inflight += 1

            def _worker(j=job):
                try:
                    self.ui.append_log(
                        "Semgrep started (%ds timeout, inflight=%d queue=%d): %s" % (
                            j["timeout"], self._semgrep_inflight, len(self._semgrep_queue), j["label"])
                    )
                    raw = run_semgrep_bridge(
                        j["py3"], j["bridge"], j["code"], j["packs"], timeout_sec=j["timeout"]
                    )
                    for f in raw:
                        f["title"] = "[%s] %s" % (j["label"], f["title"])
                        f["detail"] = "Found in %s. %s" % (j["label"], f["detail"])
                    reported = 0
                    for f in raw:
                        if f.get("severity") not in j["allowed"]:
                            continue
                        if reported >= MAX_ISSUES_PER_RESPONSE:
                            break
                        try:
                            for _k in ("title", "detail", "fix", "match", "snippet", "rule_id", "category", "severity", "confidence"):
                                if _k in f:
                                    f[_k] = _safe_text(f.get(_k))
                            issue = JsAuditIssue(
                                self._helpers,
                                j["base"],
                                j["base"].getHttpService(),
                                j["url"],
                                f
                            )
                            self._callbacks.addScanIssue(issue)
                            reported += 1
                        except Exception as ex:
                            self._stderr.println("[JS-Audit] semgrep addScanIssue: %s" % ex)
                    self.ui.append_log(
                        "Semgrep done: %s findings=%d reported=%d" % (j["label"], len(raw), reported)
                    )
                except Exception as ex:
                    self.ui.append_log("Semgrep error: %s" % ex)
                finally:
                    with self._semgrep_lock:
                        self._semgrep_inflight = max(0, self._semgrep_inflight - 1)
                    try:
                        self._semgrep_pump()
                    except Exception:
                        pass

            Thread(target=_worker).start()

    def _schedule_semgrep(self, code, label, baseRequestResponse, url, allowed):
        if not self.ui.semgrep_enabled():
            return
        if not code or len(code) < 20:
            return

        py3 = self.ui.txt_py3.getText().strip()
        bridge = self.ui.txt_bridge.getText().strip()
        packs = self.ui.semgrep_packs()
        timeout = self.ui.semgrep_timeout()
        if not packs:
            return

        sg_key = "sgjob|%s|%s" % (_sha256_text(code), ",".join(packs))
        if self._scan_cache.seen(sg_key):
            return
        self._scan_cache.mark(sg_key)

        job = {
            "code": code,
            "label": label,
            "base": baseRequestResponse,
            "url": url,
            "allowed": allowed or set(),
            "py3": py3,
            "bridge": bridge,
            "packs": packs,
            "timeout": timeout,
        }
        with self._semgrep_lock:
            if len(self._semgrep_queue) >= 32:
                self.ui.append_log("Semgrep queue full - dropping: %s" % label)
                return
            self._semgrep_queue.append(job)
        self._semgrep_pump()

    def _scan_js_fragment_fast(self, code, label):
        findings = []
        if not code:
            return findings

        base = analyze_text(code, "js_only")
        sec = scan_generic_secrets(code)
        taint = scan_source_sink_heuristic(code) if self.ui.scan_taint_enabled() else []
        allf = base + sec + taint

        # NEW: context-aware gating for noisy JS rules
        try:
            ca = ContextualAnalyzer(code, "js")
            allf = ca.run(allf)
        except Exception as ex:
            self._stderr.println("[JS-Audit] ContextualAnalyzer(js) error: %s" % ex)

        for f in allf:
            f["title"] = "[%s] %s" % (label, f["title"])
            f["detail"] = "Found in %s. %s" % (label, f["detail"])
        findings.extend(allf)
        return findings

    def _scan_js_fragment(self, code, label, baseRequestResponse=None, url=None, allowed=None, want_semgrep=False):
        findings = self._scan_js_fragment_fast(code, label)
        if want_semgrep and baseRequestResponse is not None and url is not None:
            self._schedule_semgrep(code, label, baseRequestResponse, url, allowed or set())
        return findings

    def _scan_js_fragment(self, code, label, baseRequestResponse=None, url=None, allowed=None, want_semgrep=False):
        findings = self._scan_js_fragment_fast(code, label)
        if want_semgrep and baseRequestResponse is not None and url is not None:
            self._schedule_semgrep(code, label, baseRequestResponse, url, allowed or set())
        return findings

    def scan_message(self, baseRequestResponse, manual=False):
        try:
            req_info = self._helpers.analyzeRequest(baseRequestResponse)
            url = req_info.getUrl()
            response = baseRequestResponse.getResponse()

            if response is None:
                if manual:
                    self.ui.append_log("No response to scan.")
                return []

            analyzed = self._helpers.analyzeResponse(response)
            headers = analyzed.getHeaders()
            content_type = ""
            for h in headers:
                if h.lower().startswith("content-type:"):
                    content_type = h.split(":", 1)[1].strip()
                    break

            url_str = str(url)
            text, _, body = self._body_text(baseRequestResponse)

            if body is None and text is None:
                msg = "Skip body > %d bytes: %s" % (MAX_BODY_BYTES, url_str)
                self._stdout.println("[JS-Audit] " + msg)
                if manual:
                    self.ui.append_log(msg)
                return []

            if not text:
                if manual:
                    self.ui.append_log("Empty body: %s" % url_str)
                return []

            if not manual and not self.ui.passive_enabled():
                return []

            msg_key = self._message_dedup_key(baseRequestResponse, url_str, body_text=text)
            if msg_key and not manual:
                if self._scan_cache.seen(msg_key):
                    return []
                self._scan_cache.mark(msg_key)

            kinds = classify_content(url_str, content_type, text)
            want_js = self.ui.scan_js_enabled()
            want_html = self.ui.scan_html_enabled()

            if not manual:
                if not kinds:
                    return []
                if not (("js" in kinds and want_js) or ("html" in kinds and want_html)):
                    return []

            allowed = self.ui.allowed_severities()
            if not allowed:
                if manual:
                    self.ui.append_log("No severities selected.")
                return []

            findings = []

            want_semgrep = self.ui.semgrep_enabled() and (
                manual or self.ui.semgrep_on_passive()
            )
            packs_csv = ",".join(self.ui.semgrep_packs())
            taint_on = self.ui.scan_taint_enabled()
            semgrep_on = want_semgrep

            if "html" in kinds and want_html:
                html_key = self._scan_key(url_str, "html-rules", text, False, "", False)
                if not self._scan_cache.seen(html_key):
                    html_findings = analyze_text(text, "html_only")
                    try:
                        ca_html = ContextualAnalyzer(text, "html")
                        html_findings = ca_html.run(html_findings)
                    except Exception as ex:
                        self._stderr.println("[JS-Audit] ContextualAnalyzer(html) error: %s" % ex)
                    findings.extend(html_findings)
                    self._scan_cache.mark(html_key)

                if want_js:
                    scripts = extract_inline_scripts(text)
                    for i, s in enumerate(scripts):
                        code = s["code"]
                        key = self._scan_key(url_str, "inline-script-%d" % (i + 1), code, semgrep_on, packs_csv, taint_on)
                        if self._scan_cache.seen(key):
                            continue
                        self._scan_cache.mark(key)
                        findings.extend(self._scan_js_fragment(
                            code, "inline script #%d" % (i + 1),
                            baseRequestResponse, url, allowed, want_semgrep))

                    handlers = extract_event_handler_js(text)
                    for i, h in enumerate(handlers):
                        code = h["code"]
                        key = self._scan_key(url_str, "event-%s-%d" % (h["name"], i + 1), code, semgrep_on, packs_csv, taint_on)
                        if self._scan_cache.seen(key):
                            continue
                        self._scan_cache.mark(key)
                        findings.extend(self._scan_js_fragment(
                            code, "event %s #%d" % (h["name"], i + 1),
                            baseRequestResponse, url, allowed, want_semgrep))

                    jsurls = extract_javascript_url_payloads(text)
                    for i, j in enumerate(jsurls):
                        code = j["code"]
                        key = self._scan_key(url_str, "javascript-payload-%d" % (i + 1), code, semgrep_on, packs_csv, taint_on)
                        if self._scan_cache.seen(key):
                            continue
                        self._scan_cache.mark(key)
                        findings.extend(self._scan_js_fragment(
                            code, "javascript payload #%d" % (i + 1),
                            baseRequestResponse, url, allowed, want_semgrep))

            elif "js" in kinds and want_js:
                js_key = self._scan_key(url_str, "js-response", text, semgrep_on, packs_csv, taint_on)
                if not self._scan_cache.seen(js_key):
                    self._scan_cache.mark(js_key)
                    findings.extend(self._scan_js_fragment(
                        text, "js response",
                        baseRequestResponse, url, allowed, want_semgrep))

            if manual and not kinds:
                if want_html:
                    key = self._scan_key(url_str, "manual-html-rules", text, False, "", False)
                    if not self._scan_cache.seen(key):
                        self._scan_cache.mark(key)
                        html_findings = analyze_text(text, "html_only")
                        try:
                            ca_html = ContextualAnalyzer(text, "html")
                            html_findings = ca_html.run(html_findings)
                        except Exception as ex:
                            self._stderr.println("[JS-Audit] ContextualAnalyzer(html) error: %s" % ex)
                        findings.extend(html_findings)
                if want_js:
                    key = self._scan_key(url_str, "manual-js", text, semgrep_on, packs_csv, taint_on)
                    if not self._scan_cache.seen(key):
                        self._scan_cache.mark(key)
                        findings.extend(self._scan_js_fragment(
                            text, "manual unknown",
                            baseRequestResponse, url, allowed, want_semgrep))

            filtered = []
            seen = set()
            for f in findings:
                if not _sql_finding_is_valid(f):
                    continue
                k = "%s|%s|%s|%s" % (f["rule_id"], f["line"], f["title"][:80], f["match"][:80])
                if k in seen:
                    continue
                seen.add(k)
                filtered.append(f)
            findings = filtered

            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            findings.sort(key=lambda x: (sev_rank.get(x.get("severity", "medium"), 9), x.get("line", 999999)))

            issues = []
            reported = 0
            for f in findings:
                if f.get("severity") not in allowed:
                    continue
                if reported >= MAX_ISSUES_PER_RESPONSE:
                    break
                for _k in ("title", "detail", "fix", "match", "snippet", "rule_id", "category", "severity", "confidence"):
                    if _k in f:
                        f[_k] = _safe_text(f.get(_k))
                issues.append(JsAuditIssue(
                    self._helpers,
                    baseRequestResponse,
                    baseRequestResponse.getHttpService(),
                    url,
                    f
                ))
                reported += 1

            msg = (
                "Scanned %s kinds=%s findings=%d reported=%d captured=%d "
                "scope-skipped=%d tool-skipped=%d semgrep=%s"
            ) % (
                url_str, ",".join(sorted(kinds)) if kinds else "?",
                len(findings), reported, self._capture_count,
                self._scope_skip_count, self._tool_skip_count,
                "async" if want_semgrep else "off"
            )
            self._stdout.println("[JS-Audit] " + msg)

            if manual:
                self.ui.append_log(msg)
                for iss in issues:
                    try:
                        self._callbacks.addScanIssue(iss)
                    except Exception:
                        pass

            return issues

        except Exception as ex:
            self._stderr.println("[JS-Audit] error: %s" % ex)
            if manual:
                self.ui.append_log("Error: %s" % ex)
            return []

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or not self.ui.passive_enabled():
            return
        if not self.ui.tool_enabled(toolFlag):
            self._tool_skip_count += 1
            return
        if self.ui.in_scope_only() and not self._is_in_scope(messageInfo):
            self._scope_skip_count += 1
            return

        self._capture_count += 1
        issues = self.scan_message(messageInfo, manual=False)
        for issue in issues or []:
            try:
                self._callbacks.addScanIssue(issue)
            except Exception as ex:
                self._stderr.println("[JS-Audit] addScanIssue error: %s" % ex)

    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName() and existingIssue.getUrl() == newIssue.getUrl():
            return -1
        return 0
