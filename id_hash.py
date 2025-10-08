# -*- coding: utf-8 -*-
# id_hash.py — Jython 2.7 compatible Burp extension
# Update: reduce "real words" false positives, especially in STRICT mode.
# Base64 changes:
# - Use Burp's IExtensionHelpers.base64Decode
# - Gate decoded length to common digest sizes even when STRICT is OFF
# - Tighten Base64URL regex to require '-' or '_' to avoid matching plain hex
# Defaults in this build: STRICT OFF, Base64 OFF, Base64URL OFF.
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
except Exception:
    HAS_BROTLI = False

UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
LABELLED_RE = re.compile(r'(?i)\b(md5|sha1|sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512|blake2s|blake2b|ripemd160|whirlpool)\b\s*[:=]\s*([0-9A-Fa-f]{8,256})')
B64_RE    = re.compile(r'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{12,512}={0,2})(?![A-Za-z0-9+/=])')
# Require at least one '-' or '_' so we do not collide with plain hex or standard base64
B64URL_RE = re.compile(r'(?<![A-Za-z0-9\-_])(?=[A-Za-z0-9\-_]*[-_])[A-Za-z0-9\-_]{16,512}={0,2}(?![A-Za-z0-9\-_])')
MCF_RE    = re.compile(r'(?x)(?<![A-Za-z0-9\$])(\$(?:1|2a|2b|2y|5|6)\$[^\s]{1,100}|\$(?:apr1)\$[^\s]{1,100}|\$(?:pbkdf2-sha1|pbkdf2-sha256)\$[^\s]{1,200}|\$(?:argon2id|argon2i|argon2d)\$[^\s]{1,300})(?![A-Za-z0-9\$])')

BLOCKED_CT_RE = re.compile(r'(?i)^(image/|video/|audio/|font/|application/(?:pdf|octet-stream|x-protobuf|protobuf|wasm|zip|gzip|x-gzip|x-7z-compressed|x-rar-compressed|vnd\.)|text/(?:css|javascript)|application/(?:javascript|x-javascript)|text/javascript|text/css)')

COMMON_B64_BYTE_MAPPING = {4:["crc32/adler32?"],8:["md4/md5? (trunc)","siphash?"],16:["md5","blake2s-128?"],20:["sha1","ripemd160"],24:["sha224? (padded/trunc)"],28:["sha224"],32:["sha256","blake2s","gost","snefru"],48:["sha384"],64:["sha512","blake2b","whirlpool"]}
LIKELY_DIGEST_BYTE_LENGTHS = set([16, 20, 28, 32, 48, 64])
STRICT_HEX_LENGTHS = set([32, 40, 56, 64, 96, 128])
COMMON_HEX_MEMES = set(["deadbeef","cafebabe","defaced","ba5eba11","badc0ffee","facefeed","feedface","abad1dea","c0ffee","c001d00d"])

def _byte_entropy(bs):
    try:
        if not bs: return 0.0
        counts = {}
        for b in bs: counts[b] = counts.get(b, 0) + 1
        import math
        H = 0.0
        n = float(len(bs))
        for k in counts:
            p = counts[k] / n
            H -= p * math.log(p, 2)
        return H
    except Exception:
        return 0.0

PRINTABLE_CHARS = set([ord(c) for c in (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " .,:;+-/_=!@#$%^&*()[]{}<>?\\|\"'`~\t\r\n"
)])

def _printable_ratio(bs):
    try:
        if not bs: return 0.0
        pr = 0
        for b in bs:
            if b in PRINTABLE_CHARS: pr += 1
        return float(pr) / float(len(bs))
    except Exception:
        return 0.0

def _unhex(s):
    try: return bytearray.fromhex(s)
    except Exception: return None

def _looks_like_text(bs, printable_cutoff):
    pr = _printable_ratio(bs)
    if pr >= printable_cutoff:
        try:
            s = ''.join([chr(b) for b in bs])
            if (' ' in s) or ('\n' in s) or ('\t' in s):
                return True
        except Exception:
            pass
    return False

def _englishy(bs):
    try:
        s = ''.join([chr(b) for b in bs])
    except Exception:
        return False
    if not s:
        return False
    n = float(len(s))
    letters = sum([1 for ch in s if ('A' <= ch <= 'Z') or ('a' <= ch <= 'z')])
    spaces  = s.count(' ')
    vowels  = sum([1 for ch in s.lower() if ch in 'aeiou'])
    alpha_ratio = letters / n
    space_ratio = spaces / n
    vowel_ratio = (float(vowels) / float(letters)) if letters else 0.0
    pr = _printable_ratio([ord(c) for c in s])
    if pr >= 0.9 and (alpha_ratio >= 0.6) and (space_ratio >= 0.02) and (0.25 <= vowel_ratio <= 0.5):
        return True
    return False

def _hex_digit_ratio(s):
    digits = 0
    total = 0
    for ch in s:
        if ('0' <= ch <= '9') or ('a' <= ch.lower() <= 'f'):
            total += 1
            if '0' <= ch <= '9':
                digits += 1
    if total == 0:
        return 0.0
    return float(digits) / float(total)

def _likely_digest_bytes(bs, strict, entropy_threshold, printable_cutoff, strict_exact_hex_lengths):
    if bs is None: return False
    L = len(bs)
    if strict and strict_exact_hex_lengths:
        if (L*2) not in STRICT_HEX_LENGTHS and L not in LIKELY_DIGEST_BYTE_LENGTHS: return False
    elif strict:
        if L not in LIKELY_DIGEST_BYTE_LENGTHS:
            pass
    if _byte_entropy(bs) < float(entropy_threshold): return False
    if _looks_like_text(bs, float(printable_cutoff)): return False
    if _englishy(bs): return False
    return True

def _is_meme_hex(s):
    try: return s.lower() in COMMON_HEX_MEMES
    except Exception: return False

def safe_json_load(s):
    try: return json.loads(s)
    except Exception: return None

def _get_content_type_from_headers(headers_list):
    if not headers_list: return ""
    for h in headers_list:
        try:
            hl = h.lower()
            if hl.startswith("content-type:"):
                v = h.split(":",1)[1].strip()
                return v.split(";")[0].strip().lower()
        except Exception: continue
    return ""

def _is_blocked_content_type(ct_value):
    if not ct_value: return False
    return bool(BLOCKED_CT_RE.match(ct_value))

def _is_js_path(url_path):
    try:
        if not url_path: return False
        p = url_path.split("?",1)[0].lower()
        return p.endswith(".js")
    except Exception: return False

class BurpExtender(IBurpExtender, IHttpListener, ITab, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Hash Detector (base64 gated, url strict)")

        # recall-friendly defaults
        self.min_hex_len = 16
        self.max_scan = 5000000
        self.require_context = False
        self.enable_base64 = False   # disabled by default per request
        self.enable_b64url = False   # disabled by default per request
        self.enable_mcf = True
        self.strict_mode = False
        self.strict_exact_hex_lengths = False

        # tunables
        self.entropy_threshold = 3.5
        self.printable_cutoff = 0.85
        self.strict_local_context = True  # require nearby keywords for unlabelled hits in strict mode

        # surfaces
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

        self._log("Loaded: strict OFF; Base64 OFF; Base64URL OFF. Using Burp base64Decode with digest-length gating.")

    def _init_ui(self):
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
        for cb in (self.cb_req_path,self.cb_req_query,self.cb_req_params,self.cb_req_body,self.cb_req_headers,self.cb_resp_headers,self.cb_resp_body):
            panel.add(cb)

        panel.add(JLabel("Advanced:"))
        self.cb_context = JCheckBox("Require context keywords (global)", False, actionPerformed=lambda e: self._tog('require_context', self.cb_context))
        self.cb_b64 = JCheckBox("Detect Base64 (Burp)", False, actionPerformed=lambda e: self._tog('enable_base64', self.cb_b64))
        self.cb_b64url = JCheckBox("Detect Base64URL (-,_)", False, actionPerformed=lambda e: self._tog('enable_b64url', self.cb_b64url))
        self.cb_mcf = JCheckBox("Detect MCF ($2y$, $6$, argon2id, ...)", True, actionPerformed=lambda e: self._tog('enable_mcf', self.cb_mcf))
        self.cb_strict = JCheckBox("Strict mode (entropy/length gating)", False, actionPerformed=lambda e: self._tog('strict_mode', self.cb_strict))
        self.cb_strict_exact = JCheckBox("Strict exact hex lengths", False, actionPerformed=lambda e: self._tog('strict_exact_hex_lengths', self.cb_strict_exact))
        self.cb_strict_localctx = JCheckBox("Strict: require nearby keywords for unlabelled hits", True, actionPerformed=lambda e: self._tog('strict_local_context', self.cb_strict_localctx))
        for cb in (self.cb_context,self.cb_b64,self.cb_b64url,self.cb_mcf,self.cb_strict,self.cb_strict_exact,self.cb_strict_localctx):
            panel.add(cb)

        row = JPanel(); row.setLayout(BoxLayout(row, BoxLayout.X_AXIS))
        row.add(JLabel("Min hex length:")); self.spin_min = JSpinner(SpinnerNumberModel(self.min_hex_len, 8, 256, 2)); row.add(self.spin_min)
        row.add(JLabel("Max scan bytes:")); self.spin_max = JSpinner(SpinnerNumberModel(self.max_scan, 1000, 50000000, 1000)); row.add(self.spin_max)
        panel.add(row)

        row2 = JPanel(); row2.setLayout(BoxLayout(row2, BoxLayout.X_AXIS))
        row2.add(JLabel("Entropy ≥")); self.spin_entropy = JSpinner(SpinnerNumberModel(self.entropy_threshold, 2.0, 8.0, 0.1)); row2.add(self.spin_entropy)
        row2.add(JLabel("Printable ≤")); self.spin_printable = JSpinner(SpinnerNumberModel(self.printable_cutoff, 0.5, 1.0, 0.01)); row2.add(self.spin_printable)
        apply_btn = JButton("Apply", actionPerformed=lambda e: self._apply_numeric_options()); row2.add(apply_btn)
        panel.add(row2)

        panel.add(JLabel("Extension log:")); self.log_area = JTextArea(); self.log_area.setEditable(False); self.log_area.setPreferredSize(Dimension(620,240)); panel.add(JScrollPane(self.log_area))
        self._ui = panel

    def getTabCaption(self): return "Hash Detector"
    def getUiComponent(self): return self._ui

    def _apply_numeric_options(self):
        try:
            self.min_hex_len = int(self.spin_min.getValue())
            self.max_scan = int(self.spin_max.getValue())
            self.entropy_threshold = float(self.spin_entropy.getValue())
            self.printable_cutoff = float(self.spin_printable.getValue())
            self._build_hex_regex()
            self._log("Applied: min_hex_len=%d max_scan=%d entropy>=%.2f printable<=%.2f" % (self.min_hex_len, self.max_scan, self.entropy_threshold, self.printable_cutoff))
        except Exception as e:
            self._log("Failed to apply numeric options: %s" % str(e))

    def _tog(self, attr, comp):
        try:
            setattr(self, attr, comp.isSelected())
            self._log("%s = %s" % (attr, getattr(self, attr)))
        except Exception:
            pass

    def _log(self, msg):
        try:
            self.log_area.append(msg + "\n")
            self._callbacks.printOutput(msg)
        except Exception:
            pass

    def _build_hex_regex(self):
        self.HEX_RE = re.compile(r'(?<![0-9A-Fa-f])([0-9A-Fa-f]{%d,256})(?![0-9A-Fa-f])' % self.min_hex_len)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                self._scan_request(messageInfo, attach=False)
            else:
                self._scan_response(messageInfo, attach=False)
        except Exception as e:
            self._log("Listener error: %s" % str(e))

    def doPassiveScan(self, baseRequestResponse):
        try:
            issues = []
            issues.extend(self._scan_request(baseRequestResponse, attach=True))
            issues.extend(self._scan_response(baseRequestResponse, attach=True))
            return issues or None
        except Exception as e:
            self._log("Scanner error: %s" % str(e))
            return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        try:
            if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
                return 0
        except Exception:
            pass
        return -1

    # ---------- Scanning ----------
    def _scan_request(self, messageInfo, attach):
        issues = []
        req = messageInfo.getRequest()
        if req is None:
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
                if hdr_text:
                    issues += self._scan_text(messageInfo, url, "request-headers", hdr_text, attach)
            except Exception:
                pass

        if self.scan_req_path:
            try:
                issues += self._scan_text(messageInfo, url, "request-path", path, attach)
            except Exception:
                pass
            try:
                dpath = URLDecoder.decode(path, "UTF-8")
                if dpath != path:
                    issues += self._scan_text(messageInfo, url, "request-path-decoded", dpath, attach)
            except Exception:
                pass

        if self.scan_req_query:
            try:
                q = url.getQuery() or ""
                if q:
                    issues += self._scan_text(messageInfo, url, "request-query", q, attach)
                try:
                    dq = URLDecoder.decode(q, "UTF-8")
                    if dq != q:
                        issues += self._scan_text(messageInfo, url, "request-query-decoded", dq, attach)
                except Exception:
                    pass
            except Exception:
                pass

        if self.scan_req_params:
            try:
                for p in ar.getParameters() or []:
                    try:
                        name = p.getName()
                        val = p.getValue() or ""
                        loc = "query-param:%s" % name if p.getType() == p.PARAM_URL else "body-param:%s" % name
                        issues += self._scan_text(messageInfo, url, loc, val, attach)
                    except Exception:
                        continue
            except Exception:
                pass

        if self.scan_req_body and method in ("POST","PUT","PATCH"):
            try:
                req_headers = ar.getHeaders() or []
                req_ct = _get_content_type_from_headers(req_headers)
                if _is_blocked_content_type(req_ct):
                    self._log("Skip request body due to Content-Type: %s" % (req_ct or "<none>"))
                    return issues
                off = ar.getBodyOffset()
                raw = req[off:]
                if raw and len(raw) <= self.max_scan:
                    body = self._helpers.bytesToString(raw)
                    issues += self._scan_text(messageInfo, url, "request-body", body, attach)
                    js = safe_json_load(body)
                    if isinstance(js, dict) or isinstance(js, list):
                        issues += self._scan_json(messageInfo, url, "request-body-json", js, attach)
                elif raw:
                    self._log("Skip large request body (%d bytes)" % len(raw))
            except Exception:
                pass

        if not attach:
            for i in issues:
                try:
                    self._callbacks.addScanIssue(i)
                except Exception:
                    pass
        return issues

    def _scan_response(self, messageInfo, attach):
        issues = []
        resp = messageInfo.getResponse()
        if resp is None:
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
                if hdr_text:
                    issues += self._scan_text(messageInfo, url, "response-headers", hdr_text, attach)
            except Exception:
                pass

        if self.scan_resp_body:
            try:
                headers = ar.getHeaders() or []
                resp_ct = _get_content_type_from_headers(headers)
                if _is_blocked_content_type(resp_ct):
                    self._log("Skip response body due to Content-Type: %s" % (resp_ct or "<none>"))
                    return issues
                off = ar.getBodyOffset()
                raw = resp[off:]
                if raw and len(raw) <= self.max_scan:
                    body = self._decompress_if_needed(raw, headers)
                    issues += self._scan_text(messageInfo, url, "response-body", body, attach)
                    js = safe_json_load(body)
                    if isinstance(js, dict) or isinstance(js, list):
                        issues += self._scan_json(messageInfo, url, "response-body-json", js, attach)
                elif raw:
                    self._log("Skip large response body (%d bytes)" % len(raw))
            except Exception:
                pass

        if not attach:
            for i in issues:
                try:
                    self._callbacks.addScanIssue(i)
                except Exception:
                    pass
        return issues

    # ---------- Decoding ----------
    def _decompress_if_needed(self, body_bytes, headers):
        enc = ""
        for h in headers or []:
            try:
                hl = h.lower()
                if hl.startswith("content-encoding:"):
                    enc = h.split(":", 1)[1].strip().lower()
                    break
            except Exception:
                continue
        try:
            if enc == "gzip":
                return self._helpers.bytesToString(zlib.decompress(bytearray(body_bytes), 16 + zlib.MAX_WBITS))
            if enc == "deflate":
                try:
                    return self._helpers.bytesToString(zlib.decompress(bytearray(body_bytes)))
                except Exception:
                    return self._helpers.bytesToString(zlib.decompress(bytearray(body_bytes), -zlib.MAX_WBITS))
            if enc == "br" and HAS_BROTLI:
                bis = ByteArrayInputStream(body_bytes)
                bri = BrotliInputStream(bis)
                reader = BufferedReader(InputStreamReader(bri, "UTF-8"))
                lines = []
                line = reader.readLine()
                while line is not None:
                    lines.append(line)
                    line = reader.readLine()
                return "\n".join(lines)
        except Exception:
            pass
        try:
            return self._helpers.bytesToString(body_bytes)
        except Exception:
            return ""

    # ---------- Core scanning ----------
    def _scan_text(self, messageInfo, url, where, text, attach):
        issues = []
        if not text:
            return issues

        # global context gating (optional)
        if self.require_context:
            lower = text.lower()
            has_ctx = any(k in lower for k in ("hash","sha","digest","token","hmac","checksum","md5"))
            context_conf = "Firm" if has_ctx else "Tentative"
        else:
            context_conf = "Firm"

        # MCF
        if self.enable_mcf:
            for mo in MCF_RE.finditer(text):
                cand = mo.group(1)
                issues.append(_Issue(messageInfo, url, "Hash/token (MCF)", "Firm",
                                     "Location: %s<br>Value: <b>%s</b><br>Type: MCF" % (where, cand)))

        # Labelled hex
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

        # Plain hex
        for mo in self.HEX_RE.finditer(text):
            try:
                cand = mo.group(1) or mo.group(0)
            except Exception:
                cand = mo.group(0)
            if self._skip_hex(cand) or _is_meme_hex(cand):
                continue
            if self.strict_mode and self.strict_exact_hex_lengths and (len(cand) not in STRICT_HEX_LENGTHS):
                continue
            if self.strict_mode and _hex_digit_ratio(cand) < 0.10:
                continue
            if self.strict_mode and (len(cand) not in STRICT_HEX_LENGTHS) and self.strict_local_context:
                start = max(0, mo.start() - 50)
                end = min(len(text), mo.end() + 50)
                ctx = text[start:end].lower()
                if not any(k in ctx for k in ("hash","sha","digest","md5","sha1","sha256","token","checksum","hmac")):
                    continue
            bs = _unhex(cand)
            if not _likely_digest_bytes(bs, self.strict_mode, self.entropy_threshold, self.printable_cutoff, self.strict_exact_hex_lengths):
                continue
            algs = self._guess_by_hex_len(len(cand))
            issues.append(_Issue(messageInfo, url, "Hash/token (hex)", context_conf,
                                 "Location: %s<br>Value: <b>%s</b><br>Len: %d<br>Candidates: %s" % (where, cand, len(cand), ", ".join(algs))))

        # Base64 using Burp helpers (always gate by decoded length)
        if self.enable_base64:
            for mo in B64_RE.finditer(text):
                b64 = mo.group(1)
                try:
                    jbytes = self._helpers.base64Decode(b64)
                    bs = bytearray(jbytes) if jbytes is not None else None
                except Exception:
                    continue
                if not bs:
                    continue
                if len(bs) not in LIKELY_DIGEST_BYTE_LENGTHS:
                    continue
                if not _likely_digest_bytes(bs, self.strict_mode, self.entropy_threshold, self.printable_cutoff, self.strict_exact_hex_lengths):
                    continue
                L = len(bs)
                algs = COMMON_B64_BYTE_MAPPING.get(L, [])
                conf = "Firm" if algs else "Tentative"
                issues.append(_Issue(messageInfo, url, "Hash/token (base64)", conf,
                                     "Location: %s<br>Value: <b>%s</b><br>Candidates: %s" % (where, b64, ", ".join(algs) if algs else "unknown")))

        # Base64URL using Burp helpers (regex requires '-' or '_'; gate by decoded length)
        if self.enable_b64url:
            for mo in B64URL_RE.finditer(text):
                b64u = mo.group(0)  # entire match contains at least one '-' or '_'
                norm = b64u.replace('-', '+').replace('_', '/')
                pad = (4 - (len(norm) % 4)) % 4
                norm += "=" * pad
                try:
                    jbytes = self._helpers.base64Decode(norm)
                    bs = bytearray(jbytes) if jbytes is not None else None
                except Exception:
                    continue
                if not bs:
                    continue
                if len(bs) not in LIKELY_DIGEST_BYTE_LENGTHS:
                    continue
                if not _likely_digest_bytes(bs, self.strict_mode, self.entropy_threshold, self.printable_cutoff, self.strict_exact_hex_lengths):
                    continue
                L = len(bs)
                algs = COMMON_B64_BYTE_MAPPING.get(L, [])
                conf = "Firm" if algs else "Tentative"
                issues.append(_Issue(messageInfo, url, "Hash/token (base64url)", conf,
                                     "Location: %s<br>Value: <b>%s</b><br>Candidates: %s" % (where, b64u, ", ".join(algs) if algs else "unknown")))

        if not attach:
            for issue in issues:
                try:
                    self._callbacks.addScanIssue(issue)
                except Exception:
                    pass
        return issues

    def _scan_json(self, messageInfo, url, where, js, attach):
        issues = []
        try:
            if isinstance(js, dict):
                for k, v in js.items():
                    key_name = k or ""
                    if isinstance(v, basestring):
                        issues += self._scan_text(messageInfo, url, where + ":key:" + key_name, key_name + "=" + v, attach)
                    else:
                        issues += self._scan_json(messageInfo, url, where + ":key:" + key_name, v, attach)
            elif isinstance(js, list):
                for i, item in enumerate(js):
                    issues += self._scan_json(messageInfo, url, where + ":idx:%d" % i, item, attach)
        except Exception:
            pass
        return issues

    def _skip_hex(self, s):
        if not s: return True
        if len(s) < self.min_hex_len: return True
        if UUID_RE.match(s): return True
        try:
            if len(set(s.lower())) == 1: return True
        except Exception:
            pass
        return False

    def _guess_by_hex_len(self, n):
        table = {8:["crc32/adler32?"],32:["md5"],40:["sha1","ripemd160"],48:["tiger?"],56:["sha224","sha3-224"],64:["sha256","sha3-256","blake2s","gost"],96:["sha384","sha3-384"],128:["sha512","sha3-512","blake2b","whirlpool"]}
        if n in table: return table[n]
        return ["%d-byte digest (unknown)" % (n//2)]

class _Issue(IScanIssue):
    def __init__(self, reqresp, url_obj, title, confidence, detail_html):
        self._reqresp = reqresp; self._url = url_obj; self._title = title; self._confidence = confidence; self._detail = detail_html
    def getUrl(self): return self._url
    def getIssueName(self): return self._title
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return "Information"
    def getConfidence(self): return self._confidence
    def getIssueBackground(self): return ("A value matching common hash/token formats was found. Passive detection; verify manually.")
    def getRemediationBackground(self): return ("Avoid exposing raw digests or long-lived tokens. Use opaque IDs, HMACs, salts, and short TTLs.")
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._reqresp]
    def getHttpService(self):
        try: return self._reqresp.getHttpService()
        except Exception: return None
