# -*- coding: utf-8 -*-
# id_hash.py — Jython 2.7 compatible Burp extension
# Update: Removed Base64/Base64URL detection (handled by Burp). Enhanced performance and robustness.
# Defaults: STRICT OFF, MCF ON, min_hex_len=32.

from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IScannerCheck
from javax.swing import JPanel, JCheckBox, JLabel, JButton, BoxLayout, JScrollPane, JTextArea, JSpinner
from javax.swing import SpinnerNumberModel
from java.awt import Dimension
import re
import json
import zlib
from java.io import ByteArrayInputStream, InputStreamReader, BufferedReader
from java.net import URLDecoder
try:
    from org.brotli.dec import BrotliInputStream
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

# Consolidated hash length mappings
HASH_LENGTHS = {
    'hex': {
        8: ["crc32/adler32?"], 32: ["md5"], 40: ["sha1", "ripemd160"], 48: ["tiger?"],
        56: ["sha224", "sha3-224"], 64: ["sha256", "sha3-256", "blake2s", "gost"],
        96: ["sha384", "sha3-384"], 128: ["sha512", "sha3-512", "blake2b", "whirlpool"]
    }
}
STRICT_HEX_LENGTHS = set([32, 40, 56, 64, 96, 128])
COMMON_HEX_MEMES = set(["deadbeef", "cafebabe", "defaced", "ba5eba11", "badc0ffee", "facefeed", "feedface", "abad1dea", "c0ffee", "c001d00d"])
UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
LABELLED_RE = re.compile(r'(?i)\b(md5|sha1|sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512|blake2s|blake2b|ripemd160|whirlpool)\b\s*[:=]\s*([0-9A-Fa-f]{8,256})')
MCF_RE = re.compile(r'(?x)(?<![A-Za-z0-9\$])(\$(?:1|2a|2b|2y|5|6)\$[a-zA-Z0-9./]{8,100}|\$(?:apr1)\$[a-zA-Z0-9./]{8,100}|\$(?:pbkdf2-sha256|pbkdf2-sha1)\$[a-zA-Z0-9./=]+\$[a-zA-Z0-9./=]+|\$(?:argon2id|argon2i|argon2d)\$[a-zA-Z0-9./=,\$]+\$[a-zA-Z0-9./=]+)(?![A-Za-z0-9\$])')
BLOCKED_CT_RE = re.compile(r'(?i)^(image/|video/|audio/|font/|application/(?:pdf|octet-stream|x-protobuf|protobuf|wasm|zip|gzip|x-gzip|x-7z-compressed|x-rar-compressed|vnd\.)|text/(?:css|javascript)|application/(?:javascript|x-javascript)|text/javascript|text/css)')
PRINTABLE_CHARS = set([ord(c) for c in (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;+-/_=!@#$%^&*()[]{}<>?\\|\"'`~\t\r\n"
)])

def _byte_entropy(bs):
    """Calculate the Shannon entropy of a bytearray."""
    try:
        if not bs:
            return 0.0
        counts = {}
        for b in bs:
            counts[b] = counts.get(b, 0) + 1
        import math
        H = 0.0
        n = float(len(bs))
        for k in counts:
            p = counts[k] / n
            H -= p * math.log(p, 2)
        return H
    except (ValueError, ZeroDivisionError):
        return 0.0

def _printable_ratio(bs):
    """Calculate the ratio of printable characters in a bytearray."""
    try:
        if not bs:
            return 0.0
        pr = sum(1 for b in bs if b in PRINTABLE_CHARS)
        return float(pr) / len(bs)
    except (TypeError, ZeroDivisionError):
        return 0.0

def _unhex(s):
    """Convert a hex string to a bytearray."""
    try:
        return bytearray.fromhex(s)
    except ValueError:
        return None

def _looks_like_text(bs, printable_cutoff):
    """Check if a bytearray resembles human-readable text."""
    try:
        pr = _printable_ratio(bs)
        if pr >= printable_cutoff:
            s = ''.join(chr(b) for b in bs)
            if ' ' in s or '\n' in s or '\t' in s:
                return True
    except (TypeError, UnicodeDecodeError):
        pass
    return False

def _englishy(bs):
    """Check if a bytearray resembles English text based on letter, space, and vowel ratios."""
    try:
        s = ''.join(chr(b) for b in bs)
        if not s:
            return False
        n = float(len(s))
        letters = sum(1 for ch in s if ('A' <= ch <= 'Z') or ('a' <= ch <= 'z'))
        spaces = s.count(' ')
        vowels = sum(1 for ch in s.lower() if ch in 'aeiou')
        alpha_ratio = letters / n
        space_ratio = spaces / n
        vowel_ratio = (float(vowels) / letters) if letters else 0.0
        pr = _printable_ratio([ord(c) for c in s])
        return pr >= 0.9 and alpha_ratio >= 0.6 and space_ratio >= 0.02 and 0.25 <= vowel_ratio <= 0.5
    except (TypeError, UnicodeDecodeError, ZeroDivisionError):
        return False

def _hex_digit_ratio(s):
    """Calculate the ratio of numeric digits in a hex string."""
    try:
        digits = sum(1 for ch in s if '0' <= ch <= '9')
        total = sum(1 for ch in s if ('0' <= ch <= '9') or ('a' <= ch.lower() <= 'f'))
        return float(digits) / total if total else 0.0
    except (TypeError, ZeroDivisionError):
        return 0.0

def _likely_digest_bytes(bs, strict, entropy_threshold, printable_cutoff, strict_exact_hex_lengths):
    """Check if a bytearray is likely a cryptographic hash based on entropy, length, and text characteristics."""
    if not bs:
        return False
    L = len(bs)
    if strict and strict_exact_hex_lengths and (L * 2) not in STRICT_HEX_LENGTHS:
        return False
    if _byte_entropy(bs) < float(entropy_threshold):
        return False
    if _looks_like_text(bs, float(printable_cutoff)):
        return False
    if _englishy(bs):
        return False
    return True

def _is_meme_hex(s):
    """Check if a hex string is a common meme value."""
    try:
        return s.lower() in COMMON_HEX_MEMES
    except (AttributeError, TypeError):
        return False

def safe_json_load(s):
    """Safely parse a string as JSON."""
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return None

def _get_content_type_from_headers(headers_list):
    """Extract Content-Type from headers, handling malformed cases."""
    if not headers_list:
        return ""
    for h in headers_list:
        try:
            if h.lower().startswith("content-type:"):
                parts = h.split(":", 1)
                if len(parts) < 2:
                    continue
                v = parts[1].strip()
                return v.split(";")[0].strip().lower()
        except (AttributeError, TypeError):
            continue
    return ""

def _is_blocked_content_type(ct_value):
    """Check if a Content-Type is blocked from scanning."""
    return bool(ct_value and BLOCKED_CT_RE.match(ct_value))

def _is_js_path(url_path):
    """Check if a URL path ends with .js."""
    try:
        if not url_path:
            return False
        return url_path.split("?", 1)[0].lower().endswith(".js")
    except (AttributeError, TypeError):
        return False

def _has_hex_chars(s, min_count=8):
    """Check if a string contains at least min_count hex characters."""
    try:
        return sum(1 for c in s if c in '0123456789ABCDEFabcdef') >= min_count
    except (TypeError, AttributeError):
        return False

class BurpExtender(IBurpExtender, IHttpListener, ITab, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension, set up UI, and register listeners."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Hash Detector (hex/MCF only)")
        # Defaults: stricter min_hex_len, Base64/Base64URL removed
        self.min_hex_len = 32
        self.max_scan = 5000000
        self.require_context = False
        self.enable_mcf = True
        self.strict_mode = False
        self.strict_exact_hex_lengths = False
        self.strict_local_context = True
        self.entropy_threshold = 3.5
        self.printable_cutoff = 0.85
        self.scan_req_path = True
        self.scan_req_query = True
        self.scan_req_params = True
        self.scan_req_body = True
        self.scan_req_headers = False
        self.scan_resp_headers = False
        self.scan_resp_body = True
        self._build_hex_regex()
        self._init_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        self._log("Loaded: strict OFF; MCF ON; min_hex_len=%d. Brotli: %s" % (
            self.min_hex_len, "Available" if HAS_BROTLI else "Not available"))

    def _init_ui(self):
        """Set up the configuration UI."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.add(JLabel("Scan toggles (headers OFF by default):"))
        self.cb_req_path = JCheckBox("Request Path", True, actionPerformed=lambda e: self._tog('scan_req_path', self.cb_req_path))
        self.cb_req_query = JCheckBox("Request Query (raw+decoded)", True, actionPerformed=lambda e: self._tog('scan_req_query', self.cb_req_query))
        self.cb_req_params = JCheckBox("Request Params (parsed)", True, actionPerformed=lambda e: self._tog('scan_req_params', self.cb_req_params))
        self.cb_req_body = JCheckBox("Request Body", True, actionPerformed=lambda e: self._tog('scan_req_body', self.cb_req_body))
        self.cb_req_headers = JCheckBox("Request Headers", False, actionPerformed=lambda e: self._tog('scan_req_headers', self.cb_req_headers))
        self.cb_resp_headers = JCheckBox("Response Headers", False, actionPerformed=lambda e: self._tog('scan_resp_headers', self.cb_resp_headers))
        self.cb_resp_body = JCheckBox("Response Body", True, actionPerformed=lambda e: self._tog('scan_resp_body', self.cb_resp_body))
        for cb in (self.cb_req_path, self.cb_req_query, self.cb_req_params, self.cb_req_body,
                   self.cb_req_headers, self.cb_resp_headers, self.cb_resp_body):
            panel.add(cb)
        panel.add(JLabel("Advanced:"))
        self.cb_context = JCheckBox("Require context keywords (global)", False, actionPerformed=lambda e: self._tog('require_context', self.cb_context))
        self.cb_mcf = JCheckBox("Detect MCF ($2y$, $6$, argon2id, ...)", True, actionPerformed=lambda e: self._tog('enable_mcf', self.cb_mcf))
        self.cb_strict = JCheckBox("Strict mode (entropy/length gating)", False, actionPerformed=lambda e: self._tog('strict_mode', self.cb_strict))
        self.cb_strict_exact = JCheckBox("Strict exact hex lengths", False, actionPerformed=lambda e: self._tog('strict_exact_hex_lengths', self.cb_strict_exact))
        self.cb_strict_localctx = JCheckBox("Strict: require nearby keywords for unlabelled hits", True, actionPerformed=lambda e: self._tog('strict_local_context', self.cb_strict_localctx))
        for cb in (self.cb_context, self.cb_mcf, self.cb_strict, self.cb_strict_exact, self.cb_strict_localctx):
            panel.add(cb)
        row = JPanel()
        row.setLayout(BoxLayout(row, BoxLayout.X_AXIS))
        row.add(JLabel("Min hex length:"))
        self.spin_min = JSpinner(SpinnerNumberModel(self.min_hex_len, 8, 256, 2))
        row.add(self.spin_min)
        row.add(JLabel("Max scan bytes:"))
        self.spin_max = JSpinner(SpinnerNumberModel(self.max_scan, 1000, 50000000, 1000))
        row.add(self.spin_max)
        panel.add(row)
        row2 = JPanel()
        row2.setLayout(BoxLayout(row2, BoxLayout.X_AXIS))
        row2.add(JLabel("Entropy ≥"))
        self.spin_entropy = JSpinner(SpinnerNumberModel(self.entropy_threshold, 2.0, 8.0, 0.1))
        row2.add(self.spin_entropy)
        row2.add(JLabel("Printable ≤"))
        self.spin_printable = JSpinner(SpinnerNumberModel(self.printable_cutoff, 0.5, 1.0, 0.01))
        row2.add(self.spin_printable)
        apply_btn = JButton("Apply", actionPerformed=lambda e: self._apply_numeric_options())
        row2.add(apply_btn)
        panel.add(row2)
        panel.add(JLabel("Extension log:"))
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_area.setPreferredSize(Dimension(620, 240))
        panel.add(JScrollPane(self.log_area))
        self._ui = panel

    def getTabCaption(self):
        return "Hash Detector"

    def getUiComponent(self):
        return self._ui

    def _apply_numeric_options(self):
        """Apply numeric settings from spinners and update regex."""
        try:
            self.min_hex_len = int(self.spin_min.getValue())
            self.max_scan = int(self.spin_max.getValue())
            self.entropy_threshold = float(self.spin_entropy.getValue())
            self.printable_cutoff = float(self.spin_printable.getValue())
            self._build_hex_regex()
            self._log("Applied: min_hex_len=%d max_scan=%d entropy>=%.2f printable<=%.2f" % (
                self.min_hex_len, self.max_scan, self.entropy_threshold, self.printable_cutoff))
            self.log_area.append("Settings applied successfully.\n")
        except (ValueError, TypeError) as e:
            self._log("Failed to apply numeric options: %s" % str(e))
            self.log_area.append("Error applying settings: %s\n" % str(e))

    def _tog(self, attr, comp):
        """Toggle a boolean setting and log the change."""
        try:
            setattr(self, attr, comp.isSelected())
            self._log("%s = %s" % (attr, getattr(self, attr)))
        except (AttributeError, TypeError) as e:
            self._log("Failed to toggle %s: %s" % (attr, str(e)))

    def _log(self, msg):
        """Log a message to the UI and Burp output with rolling log limit."""
        try:
            lines = self.log_area.getText().split("\n")
            if len(lines) > 1000:
                self.log_area.setText("\n".join(lines[-1000:]))
            self.log_area.append(msg + "\n")
            self._callbacks.printOutput(msg)
        except (AttributeError, TypeError):
            pass

    def _build_hex_regex(self):
        """Build the hex regex based on min_hex_len."""
        self.HEX_RE = re.compile(r'(?<![0-9A-Fa-f])([0-9A-Fa-f]{%d,256})(?![0-9A-Fa-f])' % self.min_hex_len)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages for scanning."""
        try:
            if messageIsRequest:
                return self._scan_request(messageInfo, attach=False)
            else:
                return self._scan_response(messageInfo, attach=False)
        except Exception as e:
            self._log("Listener error: %s" % str(e))

    def doPassiveScan(self, baseRequestResponse):
        """Perform passive scanning and return issues."""
        try:
            issues = []
            issues.extend(self._scan_request(baseRequestResponse, attach=True))
            issues.extend(self._scan_response(baseRequestResponse, attach=True))
            return issues or None
        except Exception as e:
            self._log("Scanner error: %s" % str(e))
            return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate scan issues."""
        try:
            if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
                return 0
        except (AttributeError, TypeError):
            pass
        return -1

    def _scan_request(self, messageInfo, attach):
        """Scan HTTP request components."""
        issues = []
        req = messageInfo.getRequest()
        if not req:
            return issues
        ar = self._helpers.analyzeRequest(req)
        url = ar.getUrl()
        path = url.getPath() or ""
        if _is_js_path(path):
            self._log("Skipping request for .js resource: %s" % str(url))
            return issues
        method = ar.getMethod().upper()
        if self.scan_req_headers:
            try:
                req_headers = ar.getHeaders() or []
                hdr_text = "\n".join(req_headers)
                if hdr_text and _has_hex_chars(hdr_text):
                    issues += self._scan_text(messageInfo, url, "request-headers", hdr_text, attach)
            except (AttributeError, TypeError) as e:
                self._log("Error scanning request headers: %s" % str(e))
        if self.scan_req_path:
            try:
                if _has_hex_chars(path):
                    issues += self._scan_text(messageInfo, url, "request-path", path, attach)
                dpath = URLDecoder.decode(path, "UTF-8")
                if dpath != path and _has_hex_chars(dpath):
                    issues += self._scan_text(messageInfo, url, "request-path-decoded", dpath, attach)
            except (UnicodeDecodeError, TypeError) as e:
                self._log("Error scanning request path: %s" % str(e))
        if self.scan_req_query:
            try:
                q = url.getQuery() or ""
                if q and _has_hex_chars(q):
                    issues += self._scan_text(messageInfo, url, "request-query", q, attach)
                dq = URLDecoder.decode(q, "UTF-8")
                if dq != q and _has_hex_chars(dq):
                    issues += self._scan_text(messageInfo, url, "request-query-decoded", dq, attach)
            except (UnicodeDecodeError, TypeError) as e:
                self._log("Error scanning request query: %s" % str(e))
        if self.scan_req_params:
            try:
                for p in ar.getParameters() or []:
                    try:
                        name = p.getName()
                        val = p.getValue() or ""
                        if _has_hex_chars(val):
                            loc = "query-param:%s" % name if p.getType() == p.PARAM_URL else "body-param:%s" % name
                            issues += self._scan_text(messageInfo, url, loc, val, attach)
                    except (AttributeError, TypeError):
                        continue
            except (AttributeError, TypeError) as e:
                self._log("Error scanning request parameters: %s" % str(e))
        if self.scan_req_body and method in ("POST", "PUT", "PATCH"):
            try:
                req_headers = ar.getHeaders() or []
                req_ct = _get_content_type_from_headers(req_headers)
                if _is_blocked_content_type(req_ct):
                    self._log("Skip request body due to Content-Type: %s for URL: %s" % (req_ct or "<none>", str(url)))
                    return issues
                off = ar.getBodyOffset()
                raw = req[off:]
                if len(raw) > self.max_scan:
                    self._log("Skip large request body (%d bytes) for URL: %s" % (len(raw), str(url)))
                    return issues
                if raw:
                    body = self._helpers.bytesToString(raw)
                    if _has_hex_chars(body):
                        issues += self._scan_text(messageInfo, url, "request-body", body, attach)
                    if req_ct == "application/json" or body.startswith(('{', '[')):
                        js = safe_json_load(body)
                        if isinstance(js, (dict, list)):
                            issues += self._scan_json(messageInfo, url, "request-body-json", js, attach)
            except (AttributeError, TypeError, UnicodeDecodeError) as e:
                self._log("Error scanning request body: %s" % str(e))
        if not attach:
            for i in issues:
                try:
                    self._callbacks.addScanIssue(i)
                except (AttributeError, TypeError):
                    self._log("Error adding scan issue: %s" % str(i))
        return issues

    def _scan_response(self, messageInfo, attach):
        """Scan HTTP response components."""
        issues = []
        resp = messageInfo.getResponse()
        if not resp:
            return issues
        ar = self._helpers.analyzeResponse(resp)
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        path = url.getPath() or ""
        if _is_js_path(path):
            self._log("Skipping response for .js resource: %s" % str(url))
            return issues
        if self.scan_resp_headers:
            try:
                headers = ar.getHeaders() or []
                hdr_text = "\n".join(headers)
                if hdr_text and _has_hex_chars(hdr_text):
                    issues += self._scan_text(messageInfo, url, "response-headers", hdr_text, attach)
            except (AttributeError, TypeError) as e:
                self._log("Error scanning response headers: %s" % str(e))
        if self.scan_resp_body:
            try:
                headers = ar.getHeaders() or []
                resp_ct = _get_content_type_from_headers(headers)
                if _is_blocked_content_type(resp_ct):
                    self._log("Skip response body due to Content-Type: %s for URL: %s" % (resp_ct or "<none>", str(url)))
                    return issues
                off = ar.getBodyOffset()
                raw = resp[off:]
                if len(raw) > self.max_scan:
                    self._log("Skip large response body (%d bytes) for URL: %s" % (len(raw), str(url)))
                    return issues
                if raw:
                    body = self._decompress_if_needed(raw, headers)
                    if _has_hex_chars(body):
                        issues += self._scan_text(messageInfo, url, "response-body", body, attach)
                    if resp_ct == "application/json" or body.startswith(('{', '[')):
                        js = safe_json_load(body)
                        if isinstance(js, (dict, list)):
                            issues += self._scan_json(messageInfo, url, "response-body-json", js, attach)
            except (AttributeError, TypeError, UnicodeDecodeError) as e:
                self._log("Error scanning response body: %s" % str(e))
        if not attach:
            for i in issues:
                try:
                    self._callbacks.addScanIssue(i)
                except (AttributeError, TypeError):
                    self._log("Error adding scan issue: %s" % str(i))
        return issues

    def _decompress_if_needed(self, body_bytes, headers):
        """Decompress response body if encoded (gzip, deflate, or Brotli)."""
        enc = ""
        for h in headers or []:
            try:
                if h.lower().startswith("content-encoding:"):
                    enc = h.split(":", 1)[1].strip().lower()
                    break
            except (AttributeError, TypeError):
                continue
        try:
            if enc == "gzip":
                return self._helpers.bytesToString(zlib.decompress(bytearray(body_bytes), 16 + zlib.MAX_WBITS))
            if enc == "deflate":
                try:
                    return self._helpers.bytesToString(zlib.decompress(bytearray(body_bytes)))
                except zlib.error:
                    return self._helpers.bytesToString(zlib.decompress(bytearray(body_bytes), -zlib.MAX_WBITS))
            if enc == "br":
                if not HAS_BROTLI:
                    self._log("Skipping Brotli-encoded response (Brotli not available)")
                    return self._helpers.bytesToString(body_bytes)
                bis = ByteArrayInputStream(body_bytes)
                bri = BrotliInputStream(bis)
                reader = BufferedReader(InputStreamReader(bri, "UTF-8"))
                lines = []
                line = reader.readLine()
                while line is not None:
                    lines.append(line)
                    line = reader.readLine()
                return "\n".join(lines)
            return self._helpers.bytesToString(body_bytes)
        except (zlib.error, UnicodeDecodeError, TypeError) as e:
            self._log("Decompression error: %s" % str(e))
            return ""

    def _scan_text(self, messageInfo, url, where, text, attach):
        """Scan text for hashes/tokens."""
        issues = []
        if not text or not _has_hex_chars(text):
            return issues
        context_conf = "Firm"
        if self.require_context:
            lower = text.lower()
            context_conf = "Firm" if any(k in lower for k in ("hash", "sha", "digest", "token", "hmac", "checksum", "md5")) else "Tentative"
        if self.enable_mcf:
            for mo in MCF_RE.finditer(text):
                cand = mo.group(1)
                issues.append(_Issue(messageInfo, url, "Hash/token (MCF)", "Firm",
                                    "Location: %s<br>Value: <b>%s</b><br>Type: MCF" % (where, cand)))
        for mo in LABELLED_RE.finditer(text):
            label = (mo.group(1) or "").lower()
            cand = mo.group(2) or ""
            if self._skip_hex(cand) or _is_meme_hex(cand):
                continue
            bs = _unhex(cand)
            if not _likely_digest_bytes(bs, self.strict_mode, self.entropy_threshold, self.printable_cutoff, self.strict_exact_hex_lengths):
                continue
            issues.append(_Issue(messageInfo, url, "Hash/token (label:%s)" % label, "Firm",
                                "Location: %s<br>Value: <b>%s</b><br>Label: %s" % (where, cand, label)))
        for mo in self.HEX_RE.finditer(text):
            try:
                cand = mo.group(1) or mo.group(0)
            except (IndexError, AttributeError):
                cand = mo.group(0)
            if self._skip_hex(cand) or _is_meme_hex(cand):
                continue
            if self.strict_mode and self.strict_exact_hex_lengths and len(cand) not in STRICT_HEX_LENGTHS:
                continue
            if self.strict_mode and _hex_digit_ratio(cand) < 0.10:
                continue
            if self.strict_mode and len(cand) not in STRICT_HEX_LENGTHS and self.strict_local_context:
                start = max(0, mo.start() - 50)
                end = min(len(text), mo.end() + 50)
                ctx = text[start:end].lower()
                if not any(k in ctx for k in ("hash", "sha", "digest", "md5", "sha1", "sha256", "token", "checksum", "hmac")):
                    continue
            bs = _unhex(cand)
            if not _likely_digest_bytes(bs, self.strict_mode, self.entropy_threshold, self.printable_cutoff, self.strict_exact_hex_lengths):
                continue
            algs = HASH_LENGTHS['hex'].get(len(cand), ["%d-byte digest (unknown)" % (len(cand) // 2)])
            issues.append(_Issue(messageInfo, url, "Hash/token (hex)", context_conf,
                                "Location: %s<br>Value: <b>%s</b><br>Len: %d<br>Candidates: %s" % (where, cand, len(cand), ", ".join(algs))))
        if not attach:
            for issue in issues:
                try:
                    self._callbacks.addScanIssue(issue)
                except (AttributeError, TypeError):
                    self._log("Error adding scan issue: %s" % str(issue))
        return issues

    def _scan_json(self, messageInfo, url, where, js, attach):
        """Scan JSON data recursively."""
        # Note: basestring used for Jython 2.7 compatibility; use str in Python 3
        try:
            basestring
        except NameError:
            basestring = str
        issues = []
        try:
            if isinstance(js, dict):
                for k, v in js.items():
                    key_name = k or ""
                    if isinstance(v, basestring):
                        if _has_hex_chars(key_name + v):
                            issues += self._scan_text(messageInfo, url, where + ":key:" + key_name, key_name + "=" + v, attach)
                    else:
                        issues += self._scan_json(messageInfo, url, where + ":key:" + key_name, v, attach)
            elif isinstance(js, list):
                for i, item in enumerate(js):
                    issues += self._scan_json(messageInfo, url, where + ":idx:%d" % i, item, attach)
        except (TypeError, AttributeError) as e:
            self._log("Error scanning JSON at %s: %s" % (where, str(e)))
        return issues

    def _skip_hex(self, s):
        """Skip invalid or non-hash hex strings."""
        try:
            if not s or len(s) < self.min_hex_len or UUID_RE.match(s) or len(set(s.lower())) == 1:
                return True
        except (TypeError, AttributeError):
            return True
        return False

    def _guess_by_hex_len(self, n):
        """Guess hash algorithms by hex length."""
        return HASH_LENGTHS['hex'].get(n, ["%d-byte digest (unknown)" % (n // 2)])

class _Issue(IScanIssue):
    def __init__(self, reqresp, url_obj, title, confidence, detail_html):
        self._reqresp = reqresp
        self._url = url_obj
        self._title = title
        self._confidence = confidence
        self._detail = detail_html

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._title

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return "A value matching common hash/token formats was found. Passive detection; verify manually."

    def getRemediationBackground(self):
        return "Avoid exposing raw digests or long-lived tokens. Use opaque IDs, HMACs, salts, and short TTLs."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self._reqresp]

    def getHttpService(self):
        try:
            return self._reqresp.getHttpService()
        except (AttributeError, TypeError):
            return None
