# -*- coding: utf-8 -*-
# id_hash_with_io_custom_dir_dedupe_csv_ignorefonts_paramnamecsv.py — Jython 2.7 compatible Burp extension
# Detects hashes in requests/responses and when found:
#   - Appends the hash to <outputDir>/hashes.txt
#   - Appends request parameter VALUES (URL + body + multipart) to <outputDir>/inputs.txt   (values only)
#   - (Optional, default ON) Also writes CSVs with timestamps:
#         <outputDir>/hashes.csv   -> "timestamp,value"
#         <outputDir>/inputs.csv   -> "timestamp,param_name,value"   (now includes param name)
# Extras:
#   - Configurable output directory (default: ~/burp-outputs) with persistence
#   - Creates output directory if missing
#   - De-duplication toggle (recent in-memory window) for both files (inputs de-duped by (name,value))
#   - Max/min input value length guards
#   - Always captures URL params even for POST/PUT/PATCH
#   - "Clear recent cache" button
#   - Skips font/static assets by both Content-Type and path extension (.woff2/.woff/.ttf/.otf/.eot/.svg/.ico, plus .js/.css/.map)
#
# Notes:
# - Cookies only scanned if Request Cookies/Headers toggled on.
# - Base64 detectors removed; focus on hex/MCF.
# - Strict mode OFF by default.

from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IScannerCheck
from javax.swing import (JPanel, JCheckBox, JLabel, JButton, BoxLayout, JScrollPane,
                         JTextArea, JSpinner, JTextField)
from javax.swing import SpinnerNumberModel
from java.awt import Dimension
import re
import json
import zlib
from java.io import ByteArrayInputStream, InputStreamReader, BufferedReader
from java.net import URLDecoder

# Java-based filesystem/time utils
from java.io import File, FileWriter, BufferedWriter, PrintWriter
from java.lang import System
from java.util import Date
from java.text import SimpleDateFormat

try:
    from org.brotli.dec import BrotliInputStream
    HAS_BROTLI = True
except Exception:
    HAS_BROTLI = False

# ---------- constants / regex ----------
HASH_LENGTHS = {
    8:  ["crc32/adler32?"],
    32: ["md5"],
    40: ["sha1", "ripemd160"],
    48: ["tiger?"],
    56: ["sha224", "sha3-224"],
    64: ["sha256", "sha3-256", "blake2s", "gost"],
    96: ["sha384", "sha3-384"],
    128:["sha512", "sha3-512", "blake2b", "whirlpool"],
}
STRICT_HEX_LENGTHS = set([32, 40, 56, 64, 96, 128])
COMMON_HEX_MEMES = set(["deadbeef","cafebabe","defaced","ba5eba11","badc0ffee","facefeed","feedface","abad1dea","c0ffee","c001d00d"])

UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
LABELLED_RE = re.compile(r'(?i)\b(md5|sha1|sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512|blake2s|blake2b|ripemd160|whirlpool)\b\s*[:=]\s*([0-9A-Fa-f]{8,256})')
MCF_RE = re.compile(r'(?x)(?<![A-Za-z0-9\$])(\$(?:1|2a|2b|2y|5|6)\$[^\s]{1,100}|\$(?:apr1)\$[^\s]{1,100}|\$(?:pbkdf2-sha1|pbkdf2-sha256)\$[^\s]{1,200}|\$(?:argon2id|argon2i|argon2d)\$[^\s]{1,300})(?![A-Za-z0-9\$])')

# Block scanning for these content-types (includes common font mime types)
BLOCKED_CT_RE = re.compile(
    r'(?i)^(?:'
    r'(?:image|video|audio|font)/|'                                  # e.g., font/woff2
    r'text/(?:css|javascript)|'                                      # text/css, text/javascript
    r'application/(?:'
        r'pdf|octet-stream|x-protobuf|protobuf|wasm|zip|gzip|x-gzip|'
        r'x-7z-compressed|x-rar-compressed|vnd\.|javascript|x-javascript|'
        r'font-woff2?|x-font-ttf|x-font-otf|x-font-woff|font-ttf|font-otf'
    r')'
    r')'
)

PRINTABLE_CHARS = set([ord(c) for c in (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;+-/_=!@#$%^&*()[]{}<>?\\|\"'`~\t\r\n"
)])

# Extensions to skip early by path
IGNORED_EXTS = (".js", ".css", ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".svg", ".ico")

# ---------- helpers ----------
def _byte_entropy(bs):
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
    except Exception:
        return 0.0

def _printable_ratio(bs):
    try:
        if not bs:
            return 0.0
        pr = 0
        for b in bs:
            if b in PRINTABLE_CHARS:
                pr += 1
        return float(pr) / float(len(bs))
    except Exception:
        return 0.0

def _unhex(s):
    try:
        return bytearray.fromhex(s)
    except Exception:
        return None

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
    if pr >= 0.9 and (alpha_ratio >= 0.6) and (space_ratio >= 0.02):
        return True
    return False

def _hex_digit_ratio(s):
    try:
        digits = 0
        total = 0
        for ch in s:
            if ('0' <= ch <= '9') or ('a' <= ch.lower() <= 'f'):
                total += 1
                if '0' <= ch <= '9':
                    digits += 1
        return float(digits) / float(total) if total else 0.0
    except Exception:
        return 0.0

def _likely_digest_bytes(bs, strict, entropy_threshold, printable_cutoff, strict_exact_hex_lengths):
    if bs is None:
        return False
    L = len(bs)
    if strict and strict_exact_hex_lengths:
        if (L*2) not in STRICT_HEX_LENGTHS:
            return False
    if _byte_entropy(bs) < float(entropy_threshold):
        return False
    if _looks_like_text(bs, float(printable_cutoff)):
        return False
    if _englishy(bs):
        return False
    return True

def _is_meme_hex(s):
    try:
        return s.lower() in COMMON_HEX_MEMES
    except Exception:
        return False

def safe_json_load(s):
    try:
        return json.loads(s)
    except Exception:
        return None

def _get_content_type_from_headers(headers_list):
    if not headers_list:
        return ""
    for h in headers_list:
        try:
            hl = h.lower()
            if hl.startswith("content-type:"):
                v = h.split(":",1)[1].strip()
                return v.split(";")[0].strip().lower()
        except Exception:
            continue
    return ""

def _is_blocked_content_type(ct_value):
    if not ct_value:
        return False
    return bool(BLOCKED_CT_RE.match(ct_value))

def _is_ignored_path(url_path):
    try:
        if not url_path:
            return False
        p = url_path.split("?", 1)[0].lower()
        return any(p.endswith(ext) for ext in IGNORED_EXTS)
    except Exception:
        return False

# ---------- Burp extender ----------
class BurpExtender(IBurpExtender, IHttpListener, ITab, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Hash Detector (requests+responses)")

        # Defaults
        self.min_hex_len = 8
        self.max_scan = 5000000
        self.require_context = False
        self.enable_mcf = True
        self.strict_mode = False
        self.strict_exact_hex_lengths = False
        self.strict_local_context = True
        self.entropy_threshold = 3.5
        self.printable_cutoff = 0.85

        # Surfaces
        self.scan_req_path = True
        self.scan_req_query = True     # include URL params even on POST/PUT/PATCH
        self.scan_req_params = True
        self.scan_req_body = True
        self.scan_req_headers = False
        self.scan_req_cookies = False
        self.scan_resp_headers = False
        self.scan_resp_body = True

        # Output / dedupe / bounds
        self.dedupe_enabled = True
        self.csv_enabled = True
        self.max_value_len = 4096
        self.min_value_len = 1
        self._dedupe_window = 5000   # recent unique entries to remember per file
        self._recent_hashes = []
        self._recent_hashes_set = set()
        self._recent_inputs = []
        self._recent_inputs_set = set()

        self._tsfmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ")

        self._build_hex_regex()
        self._init_paths()     # default dir or last saved
        self._init_ui()

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)

        self._log("Loaded: request + response scanning enabled. Strict OFF; headers OFF by default; cookies OFF by default.")
        self._log("hashes.txt -> " + self.hashes_path.getAbsolutePath())
        self._log("inputs.txt -> " + self.inputs_path.getAbsolutePath())
        self._log("hashes.csv -> " + self.hashes_csv.getAbsolutePath())
        self._log("inputs.csv -> " + self.inputs_csv.getAbsolutePath())

    # Determine default directory (~/burp-outputs) and load saved setting if present
    def _init_paths(self):
        try:
            saved = self._callbacks.loadExtensionSetting("outputDir")
        except Exception:
            saved = None
        if saved and len(saved.strip()) > 0:
            out_dir = File(saved)
        else:
            user_home = System.getProperty("user.home")
            out_dir = File(user_home, "burp-outputs")
        self._ensure_dir(out_dir)
        self.output_dir = out_dir
        self.hashes_path = File(self.output_dir, "hashes.txt")
        self.inputs_path = File(self.output_dir, "inputs.txt")
        self.hashes_csv = File(self.output_dir, "hashes.csv")
        self.inputs_csv = File(self.output_dir, "inputs.csv")

    # Create directory if missing
    def _ensure_dir(self, fdir):
        try:
            if (not fdir.exists()) or (not fdir.isDirectory()):
                fdir.mkdirs()
        except Exception as e:
            try:
                user_home = System.getProperty("user.home")
                fallback = File(user_home, "burp-outputs")
                if (not fallback.exists()) or (not fallback.isDirectory()):
                    fallback.mkdirs()
                self.output_dir = fallback
            except Exception:
                pass

    def _init_ui(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        # Scan toggles
        panel.add(JLabel("Scan toggles (headers & cookies OFF by default):"))
        self.cb_req_path = JCheckBox("Request Path", True, actionPerformed=lambda e: self._tog('scan_req_path', self.cb_req_path))
        self.cb_req_query = JCheckBox("Request Query (raw+decoded)", True, actionPerformed=lambda e: self._tog('scan_req_query', self.cb_req_query))
        self.cb_req_params = JCheckBox("Request Params (parsed)", True, actionPerformed=lambda e: self._tog('scan_req_params', self.cb_req_params))
        self.cb_req_body = JCheckBox("Request Body", True, actionPerformed=lambda e: self._tog('scan_req_body', self.cb_req_body))
        self.cb_req_headers = JCheckBox("Request Headers", False, actionPerformed=lambda e: self._tog('scan_req_headers', self.cb_req_headers))
        self.cb_req_cookies = JCheckBox("Request Cookies", False, actionPerformed=lambda e: self._tog('scan_req_cookies', self.cb_req_cookies))
        self.cb_resp_headers = JCheckBox("Response Headers", False, actionPerformed=lambda e: self._tog('scan_resp_headers', self.cb_resp_headers))
        self.cb_resp_body = JCheckBox("Response Body", True, actionPerformed=lambda e: self._tog('scan_resp_body', self.cb_resp_body))
        for cb in (self.cb_req_path,self.cb_req_query,self.cb_req_params,self.cb_req_body,self.cb_req_headers,self.cb_resp_headers,self.cb_resp_body):
            panel.add(cb)

        # Advanced
        panel.add(JLabel("Advanced:"))
        self.cb_context = JCheckBox("Require context keywords (global)", False, actionPerformed=lambda e: self._tog('require_context', self.cb_context))
        self.cb_mcf = JCheckBox("Detect MCF ($2y$, $6$, argon2id, ...)", True, actionPerformed=lambda e: self._tog('enable_mcf', self.cb_mcf))
        self.cb_strict = JCheckBox("Strict mode (entropy/length gating)", False, actionPerformed=lambda e: self._tog('strict_mode', self.cb_strict))
        self.cb_strict_exact = JCheckBox("Strict exact hex lengths", False, actionPerformed=lambda e: self._tog('strict_exact_hex_lengths', self.cb_strict_exact))
        self.cb_strict_localctx = JCheckBox("Strict: require nearby keywords for unlabelled hits", True, actionPerformed=lambda e: self._tog('strict_local_context', self.cb_strict_localctx))
        for cb in (self.cb_context,self.cb_mcf,self.cb_strict,self.cb_strict_exact,self.cb_strict_localctx):
            panel.add(cb)

        # Numeric options
        row = JPanel(); row.setLayout(BoxLayout(row, BoxLayout.X_AXIS))
        row.add(JLabel("Min hex length:")); self.spin_min = JSpinner(SpinnerNumberModel(self.min_hex_len, 8, 256, 2)); row.add(self.spin_min)
        row.add(JLabel("Max scan bytes:")); self.spin_max = JSpinner(SpinnerNumberModel(self.max_scan, 1000, 50000000, 1000)); row.add(self.spin_max)
        panel.add(row)

        row2 = JPanel(); row2.setLayout(BoxLayout(row2, BoxLayout.X_AXIS))
        row2.add(JLabel("Entropy \u2265")); self.spin_entropy = JSpinner(SpinnerNumberModel(self.entropy_threshold, 2.0, 8.0, 0.1)); row2.add(self.spin_entropy)
        row2.add(JLabel("Printable \u2264")); self.spin_printable = JSpinner(SpinnerNumberModel(self.printable_cutoff, 0.5, 1.0, 0.01)); row2.add(self.spin_printable)
        row2.add(JLabel("Max input length")); self.spin_maxval = JSpinner(SpinnerNumberModel(self.max_value_len, 128, 1000000, 128)); row2.add(self.spin_maxval)
        row2.add(JLabel("Min input length")); self.spin_minval = JSpinner(SpinnerNumberModel(self.min_value_len, 0, 8192, 1)); row2.add(self.spin_minval)
        panel.add(row2)

        # Dedupe + CSV toggle + Clear cache
        self.cb_dedupe = JCheckBox("De-duplicate outputs (recent)", True, actionPerformed=lambda e: self._tog('dedupe_enabled', self.cb_dedupe))
        self.cb_csv = JCheckBox("Write CSV with timestamps", True, actionPerformed=lambda e: self._tog('csv_enabled', self.cb_csv))
        panel.add(self.cb_dedupe)
        panel.add(self.cb_csv)

        apply_btn = JButton("Apply", actionPerformed=lambda e: self._apply_numeric_options())
        clear_btn = JButton("Clear recent cache", actionPerformed=lambda e: self._clear_recent_cache())
        panel.add(apply_btn)
        panel.add(clear_btn)

        # Output directory controls
        panel.add(JLabel("Output directory (hashes/inputs .txt & .csv will be written here):"))
        self.dir_field = JTextField(self.output_dir.getAbsolutePath(), 40)
        dir_row = JPanel(); dir_row.setLayout(BoxLayout(dir_row, BoxLayout.X_AXIS))
        dir_row.add(self.dir_field)
        apply_dir_btn = JButton("Apply Dir", actionPerformed=lambda e: self._apply_output_dir())
        dir_row.add(apply_dir_btn)
        panel.add(dir_row)

        panel.add(JLabel("Extension log:"))
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_area.setPreferredSize(Dimension(620,240))
        panel.add(JScrollPane(self.log_area))

        self._ui = panel

    def getTabCaption(self): return "Hash Detector"
    def getUiComponent(self): return self._ui

    def _apply_numeric_options(self):
        try:
            self.min_hex_len = int(self.spin_min.getValue())
            self.max_scan = int(self.spin_max.getValue())
            self.entropy_threshold = float(self.spin_entropy.getValue())
            self.printable_cutoff = float(self.spin_printable.getValue())
            self.max_value_len = int(self.spin_maxval.getValue())
            self.min_value_len = int(self.spin_minval.getValue())
            self._build_hex_regex()
            self._log("Applied: min_hex_len=%d max_scan=%d entropy>=%.2f printable<=%.2f max_input_len=%d min_input_len=%d dedupe=%s csv=%s" %
                      (self.min_hex_len, self.max_scan, self.entropy_threshold, self.printable_cutoff,
                       self.max_value_len, self.min_value_len, str(self.dedupe_enabled), str(self.csv_enabled)))
        except Exception as e:
            self._log("Failed to apply numeric options: %s" % str(e))

    def _apply_output_dir(self):
        try:
            raw = self.dir_field.getText()
            if not raw or len(raw.strip()) == 0:
                self._log("Directory path empty; ignoring.")
                return
            new_dir = File(raw.strip())
            if not new_dir.isAbsolute():
                user_home = System.getProperty("user.home")
                new_dir = File(File(user_home).getAbsolutePath(), raw.strip())
            self._ensure_dir(new_dir)
            self.output_dir = new_dir
            self.hashes_path = File(self.output_dir, "hashes.txt")
            self.inputs_path = File(self.output_dir, "inputs.txt")
            self.hashes_csv = File(self.output_dir, "hashes.csv")
            self.inputs_csv = File(self.output_dir, "inputs.csv")
            try:
                self._callbacks.saveExtensionSetting("outputDir", self.output_dir.getAbsolutePath())
            except Exception:
                pass
            self._log("Output dir set to: " + self.output_dir.getAbsolutePath())
            self._log("hashes.txt -> " + self.hashes_path.getAbsolutePath())
            self._log("inputs.txt -> " + self.inputs_path.getAbsolutePath())
            self._log("hashes.csv -> " + self.hashes_csv.getAbsolutePath())
            self._log("inputs.csv -> " + self.inputs_csv.getAbsolutePath())
        except Exception as e:
            self._log("Failed to set output directory: %s" % str(e))

    def _clear_recent_cache(self):
        try:
            self._recent_hashes = []
            self._recent_hashes_set = set()
            self._recent_inputs = []
            self._recent_inputs_set = set()
            self._log("Cleared recent de-duplication cache.")
        except Exception as e:
            self._log("Failed to clear cache: %s" % str(e))

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

    # ---------- File IO ----------
    def _append_file(self, file_obj, text):
        try:
            fw = FileWriter(file_obj, True)  # append
            bw = BufferedWriter(fw)
            pw = PrintWriter(bw)
            try:
                pw.println(text)
            finally:
                try: pw.close()
                except Exception: pass
                try: bw.close()
                except Exception: pass
                try: fw.close()
                except Exception: pass
        except Exception as e:
            try:
                self._callbacks.printError("Failed writing to %s: %s" % (file_obj.getAbsolutePath(), str(e)))
            except Exception:
                pass

    def _append_csv(self, file_obj, cells):
        try:
            # cells: list of strings; we will quote if needed
            # If file is empty, add header for first write
            need_header = (not file_obj.exists()) or (file_obj.length() == 0)
            fw = FileWriter(file_obj, True)
            bw = BufferedWriter(fw)
            pw = PrintWriter(bw)
            try:
                if need_header:
                    # Choose header based on which CSV we're writing
                    if "inputs.csv" in file_obj.getName():
                        pw.println("timestamp,param_name,value")
                    else:
                        pw.println("timestamp,value")
                def q(s):
                    if s is None:
                        return ""
                    s = str(s)
                    if ('"' in s) or (',' in s) or ('\n' in s) or ('\r' in s):
                        s = '"' + s.replace('"','""') + '"'
                    return s
                pw.println(",".join([q(c) for c in cells]))
            finally:
                try: pw.close()
                except Exception: pass
                try: bw.close()
                except Exception: pass
                try: fw.close()
                except Exception: pass
        except Exception as e:
            try:
                self._callbacks.printError("Failed writing CSV to %s: %s" % (file_obj.getAbsolutePath(), str(e)))
            except Exception:
                pass

    def _now_ts(self):
        try:
            return self._tsfmt.format(Date())
        except Exception:
            return ""

    # ---------- De-dupe helpers ----------
    def _recent_add(self, kind, key):
        try:
            if kind == "hash":
                if key in self._recent_hashes_set:
                    return False
                self._recent_hashes.append(key)
                self._recent_hashes_set.add(key)
                if len(self._recent_hashes) > self._dedupe_window:
                    old = self._recent_hashes.pop(0)
                    try: self._recent_hashes_set.remove(old)
                    except Exception: pass
                return True
            else:
                if key in self._recent_inputs_set:
                    return False
                self._recent_inputs.append(key)
                self._recent_inputs_set.add(key)
                if len(self._recent_inputs) > self._dedupe_window:
                    old = self._recent_inputs.pop(0)
                    try: self._recent_inputs_set.remove(old)
                    except Exception: pass
                return True
        except Exception:
            return True  # fail open

    def _should_write_hash(self, hashval):
        if not hashval:
            return False
        if not self.dedupe_enabled:
            return True
        return self._recent_add("hash", hashval)

    def _mk_input_key(self, name, val):
        try:
            n = "" if name is None else str(name)
            v = "" if val is None else str(val)
            return n + "=" + v
        except Exception:
            return str(name) + "=" + str(val)

    def _should_write_input(self, name, val):
        if val is None:
            return False
        if self.max_value_len > 0 and len(val) > self.max_value_len:
            return False
        if self.min_value_len > 0 and len(val) < self.min_value_len:
            return False
        if not self.dedupe_enabled:
            return True
        return self._recent_add("input", self._mk_input_key(name, val))

    def _write_hash(self, hashval):
        if self._should_write_hash(hashval):
            self._append_file(self.hashes_path, hashval)
            if self.csv_enabled:
                self._append_csv(self.hashes_csv, [self._now_ts(), hashval])

    def _write_input(self, name, val):
        if self._should_write_input(name, val):
            # .txt remains value-only per original requirement
            self._append_file(self.inputs_path, val)
            if self.csv_enabled:
                self._append_csv(self.inputs_csv, [self._now_ts(), (name or ""), val])

    # ---------- Collect request param (NAME, VALUE) pairs (URL + body + multipart) ----------
    def _save_request_inputs(self, messageInfo):
        try:
            ar = None
            try:
                ar = self._helpers.analyzeRequest(messageInfo)
            except Exception:
                req = messageInfo.getRequest()
                if req:
                    ar = self._helpers.analyzeRequest(req)

            collected = []  # list of (name, value)

            # Always collect URL params + body/json/xml/multipart attrs
            if ar:
                for p in ar.getParameters() or []:
                    try:
                        t = p.getType()
                        if t in (p.PARAM_URL, p.PARAM_BODY, p.PARAM_JSON, p.PARAM_XML, p.PARAM_XML_ATTR, p.PARAM_MULTIPART_ATTR):
                            name = p.getName()
                            val = p.getValue()
                            if val:
                                collected.append((name, val))
                    except Exception:
                        continue

            # Multipart fallback (extract name from Content-Disposition)
            try:
                req = messageInfo.getRequest()
                if req and ar:
                    headers = ar.getHeaders() or []
                    ct = ""
                    for h in headers:
                        try:
                            hl = h.lower()
                            if hl.startswith("content-type:"):
                                ct = h.split(":",1)[1].strip()
                                break
                        except Exception:
                            continue
                    if ct and 'multipart/form-data' in ct.lower():
                        off = ar.getBodyOffset()
                        raw = req[off:]
                        if raw:
                            body = self._helpers.bytesToString(raw)
                            if body:
                                m = re.search(r'boundary=([^\s;]+)', ct, re.I)
                                if m:
                                    boundary = m.group(1)
                                    if boundary.startswith('"') and boundary.endswith('"'):
                                        boundary = boundary[1:-1]
                                    parts = body.split("--" + boundary)
                                    for part in parts:
                                        if not part or part.strip() == "--":
                                            continue
                                        idx = part.find("\r\n\r\n")
                                        if idx == -1:
                                            idx = part.find("\n\n")
                                        if idx != -1:
                                            hdr = part[:idx]
                                            val = part[idx+4:] if part[idx:idx+4].startswith("\r\n\r\n") else part[idx+2:]
                                            # Skip files
                                            if re.search(r'Content-Disposition:.*?filename\s*=\s*"', hdr, re.I):
                                                continue
                                            # Try to get the "name" attribute
                                            name_m = re.search(r'name="([^"]*)"', hdr, re.I)
                                            pname = name_m.group(1) if name_m else ""
                                            val = val.strip()
                                            if val:
                                                collected.append((pname, val))
            except Exception:
                pass

            for (n, v) in collected:
                self._write_input(n, v)

        except Exception:
            pass

    # ---------- Scanning ----------
    def _scan_request(self, messageInfo, attach):
        issues = []
        try:
            ar = self._helpers.analyzeRequest(messageInfo)
        except Exception:
            req = messageInfo.getRequest()
            if not req:
                return issues
            ar = self._helpers.analyzeRequest(req)

        req = messageInfo.getRequest()
        if not req:
            return issues

        try:
            url = ar.getUrl()
        except Exception:
            url = None
        if url is None:
            try:
                url = self._helpers.analyzeRequest(req).getUrl()
            except Exception:
                url = None

        path = (url.getPath() if url else "") or ""
        if _is_ignored_path(path):
            self._log("Skipping ignored asset path: %s" % (str(url) if url else "<no-url>"))
            return issues

        method = ar.getMethod().upper() if ar else "GET"

        if self.scan_req_headers:
            try:
                req_headers = ar.getHeaders() or []
                hdr_text = "\n".join(req_headers)
                issues += self._scan_text(messageInfo, url, "request-headers", hdr_text, attach)
            except Exception:
                pass

        if self.scan_req_path:
            try:
                issues += self._scan_text(messageInfo, url, "request-path", path, attach)
                try:
                    dpath = URLDecoder.decode(path, "UTF-8")
                    if dpath != path:
                        issues += self._scan_text(messageInfo, url, "request-path-decoded", dpath, attach)
                except Exception:
                    pass
            except Exception:
                pass

        if self.scan_req_query:
            try:
                q = url.getQuery() or ""
            except Exception:
                q = ""
            if q:
                issues += self._scan_text(messageInfo, url, "request-query", q, attach)
                try:
                    dq = URLDecoder.decode(q, "UTF-8")
                    if dq != q:
                        issues += self._scan_text(messageInfo, url, "request-query-decoded", dq, attach)
                except Exception:
                    pass

        if self.scan_req_params:
            try:
                for p in ar.getParameters() or []:
                    try:
                        t = p.getType()
                        name = p.getName()
                        val = p.getValue() or ""
                        if t == p.PARAM_URL:
                            loc = "query-param:%s" % name
                            issues += self._scan_text(messageInfo, url, loc, val, attach)
                        elif t in (p.PARAM_BODY, p.PARAM_JSON, p.PARAM_XML, p.PARAM_XML_ATTR, p.PARAM_MULTIPART_ATTR):
                            loc = "body-param:%s" % name
                            issues += self._scan_text(messageInfo, url, loc, val, attach)
                        elif t == p.PARAM_COOKIE:
                            if self.scan_req_cookies or self.scan_req_headers:
                                loc = "cookie:%s" % name
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
                else:
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
        if not resp:
            return issues
        ar = self._helpers.analyzeResponse(resp)
        try:
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
        except Exception:
            url = None

        path = (url.getPath() if url else "") or ""
        if _is_ignored_path(path):
            self._log("Skipping ignored asset path: %s" % (str(url) if url else "<no-url>"))
            return issues

        if self.scan_resp_headers:
            try:
                headers = ar.getHeaders() or []
                hdr_text = "\n".join(headers)
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

    # ---------- decompression ----------
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

    # ---------- core text/JSON scanning ----------
    def _scan_text(self, messageInfo, url, where, text, attach):
        issues = []
        if not text:
            return issues

        if self.require_context:
            lower = text.lower()
            context_conf = "Firm" if any(k in lower for k in ("hash","sha","digest","token","hmac","checksum","md5")) else "Tentative"
        else:
            context_conf = "Firm"

        # MCF
        if self.enable_mcf:
            for mo in MCF_RE.finditer(text):
                cand = mo.group(1)
                try:
                    self._write_hash(cand)
                    self._save_request_inputs(messageInfo)
                except Exception:
                    pass
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
            try:
                self._write_hash(cand)
                self._save_request_inputs(messageInfo)
            except Exception:
                pass
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
                if not any(k in ctx for k in ("hash","sha","digest","md5","sha1","sha256","token","checksum","hmac")) \
                        and not where.startswith(("request-path","request-query","query-param","body-param")):
                    continue
            bs = _unhex(cand)
            if not _likely_digest_bytes(bs, self.strict_mode, self.entropy_threshold, self.printable_cutoff, self.strict_exact_hex_lengths):
                continue
            try:
                self._write_hash(cand)
                self._save_request_inputs(messageInfo)
            except Exception:
                pass
            algs = HASH_LENGTHS.get(len(cand), ["%d-byte digest (unknown)" % (len(cand)//2)])
            issues.append(_Issue(messageInfo, url, "Hash/token (hex)", context_conf,
                                 "Location: %s<br>Value: <b>%s</b><br>Len: %d<br>Candidates: %s" % (where, cand, len(cand), ", ".join(algs))))

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
            basestring
        except NameError:
            basestring = str
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
        try:
            if not s:
                return True
            if len(s) < self.min_hex_len:
                return True
            if UUID_RE.match(s):
                return True
            if len(set(s.lower())) == 1:
                return True
        except Exception:
            return True
        return False

class _Issue(IScanIssue):
    def __init__(self, reqresp, url_obj, title, confidence, detail_html):
        self._reqresp = reqresp; self._url = url_obj; self._title = title; self._confidence = confidence; self._detail = detail_html
    def getUrl(self): return self._url
    def getIssueName(self): return self._title
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return "Information"
    def getConfidence(self): return self._confidence
    def getIssueBackground(self): return "A value matching common hash/token formats was found. Passive detection; verify manually."
    def getRemediationBackground(self): return "Avoid exposing raw digests or long-lived tokens. Use opaque IDs, HMACs, salts, and short TTLs."
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._reqresp]
    def getHttpService(self):
        try: return self._reqresp.getHttpService()
        except Exception: return None
