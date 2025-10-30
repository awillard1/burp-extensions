// LZStringDetector.java
// Burp Suite Java Extension – Detects & decodes LZ-String (EncodedURIComponent, Base64, UTF16)
// - Pure-Java port (no JS engine).
// - EU fast-path on entire path segment.
// - Strict heuristics to cut false positives (toggleable in UI).
// - Canonical URL-decode chain (handles double-encoding) across path/query/params/headers/body.
// - Grid shows Token (pre-decoded/matched layer) and Decoded; detail dialog shows both.

import burp.*;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class LZStringDetector implements IBurpExtender, IHttpListener, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    // ================= Tunables / Patterns =================
    private static final int MIN_TOKEN_LEN        = 10;     // conservative to avoid noise
    private static final int MIN_TOKEN_LEN_B64    = 12;     // base64-ish tokens tend to be longer
    private static final int MAX_DECODE_LEN       = 16384;  // safety upper bound

    private static final String SAVE_DIR = System.getProperty("user.home")
            + File.separator + "burp-outputs" + File.separator + "lz_decoded";

    // Alphabets used by LZ-String
    private static final String EU_ALPHA  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$";
    private static final String B64_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Candidate extraction: we URL-decode layers separately; no raw '%' in candidate pattern
    private static final Pattern CANDIDATE = Pattern.compile("[A-Za-z0-9_\\-\\+\\$]{" + MIN_TOKEN_LEN + ",}");
    private static final Pattern BASE64ISH = Pattern.compile("^[A-Za-z0-9_\\-+/=]{" + MIN_TOKEN_LEN_B64 + ",}$");

    // UI toggles
    private boolean scopeOnly      = true;
    private boolean readableOnly   = true;  // keep; quality gate is stronger now
    private boolean strictMode     = true;  // strong heuristics ON by default
    private boolean logAllAttempts = false; // optional verbose logging

    // UI
    private JPanel panel;
    private JTable resultsTable;
    private ResultsTableModel tableModel;
    private final List<DecodeResult> results = new ArrayList<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
        this.callbacks = cb;
        this.helpers   = cb.getHelpers();
        this.stdout    = new PrintWriter(cb.getStdout(), true);
        this.stderr    = new PrintWriter(cb.getStderr(), true);

        cb.setExtensionName("LZString Detector (Java)");
        cb.registerHttpListener(this);
        new File(SAVE_DIR).mkdirs();
        buildUI();
        cb.addSuiteTab(this);

        stdout.println("[LZString] Extension loaded.");
    }

    private void buildUI() {
        panel = new JPanel(new BorderLayout());

        JPanel top = new JPanel(new GridLayout(1, 8));
        top.setBorder(BorderFactory.createTitledBorder("Config"));

        JCheckBox cbScope = new JCheckBox("Scope only", scopeOnly);
        cbScope.addActionListener(e -> scopeOnly = cbScope.isSelected());
        top.add(cbScope);

        JCheckBox cbReadable = new JCheckBox("Readable only", readableOnly);
        cbReadable.addActionListener(e -> readableOnly = cbReadable.isSelected());
        top.add(cbReadable);

        JCheckBox cbStrict = new JCheckBox("Strict mode", strictMode);
        cbStrict.addActionListener(e -> strictMode = cbStrict.isSelected());
        top.add(cbStrict);

        JCheckBox cbLog = new JCheckBox("Verbose attempts", logAllAttempts);
        cbLog.addActionListener(e -> logAllAttempts = cbLog.isSelected());
        top.add(cbLog);

        JButton btnIssues = new JButton("Create Issues");
        btnIssues.addActionListener(e -> createIssues());
        top.add(btnIssues);

        JButton btnExport = new JButton("Export ZIP");
        btnExport.addActionListener(e -> exportToZip());
        top.add(btnExport);

        JButton btnTest = new JButton("Test Decode");
        btnTest.addActionListener(e -> testManualDecode());
        top.add(btnTest);

        panel.add(top, BorderLayout.NORTH);

        tableModel = new ResultsTableModel();
        resultsTable = new JTable(tableModel);
        resultsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent e) {
                int row = resultsTable.rowAtPoint(e.getPoint());
                if (row >= 0 && e.getClickCount() == 2) showDetailDialog(results.get(row));
            }
        });
        panel.add(new JScrollPane(resultsTable), BorderLayout.CENTER);
    }

    @Override public String getTabCaption() { return "LZString"; }
    @Override public Component getUiComponent() { return panel; }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) return;
        IRequestInfo req = helpers.analyzeRequest(messageInfo);
        if (scopeOnly && !callbacks.isInScope(req.getUrl())) return;

        final String tool = callbacks.getToolName(toolFlag);
        final URL url = req.getUrl();

        // ===== PATH handling: split raw path, and also split decoded variants =====
        String path = url.getPath();
        if (path != null && !path.isEmpty()) {
            // Build raw + decoded layers for the *entire* path first
            List<String> pathLayers = urlDecodeChain3(path);

            for (int li = 0; li < pathLayers.size(); li++) {
                String pLayer = pathLayers.get(li);
                String layerTag = (li == 0 ? "" : "-dec" + li);

                String normalized = pLayer;
                if (normalized.startsWith("/")) normalized = normalized.substring(1);
                if (normalized.endsWith("/")) normalized = normalized.substring(0, normalized.length() - 1);
                if (normalized.isEmpty()) continue;

                String[] segs = normalized.split("/");
                for (int si = 0; si < segs.length; si++) {
                    String seg = segs[si];
                    if (seg == null || seg.isEmpty()) continue;

                    // Segment-level: also decode twice (handles double-encoded segments)
                    for (String segLayer : urlDecodeChain2(seg)) {
                        harvestAndTry(segLayer, messageInfo, true, tool, "path-seg[" + si + "]" + layerTag);
                        if (segLayer.contains(";")) {
                            String main = segLayer.split(";", 2)[0];
                            String params = segLayer.substring(segLayer.indexOf(';') + 1);
                            if (!main.isEmpty()) harvestAndTry(main, messageInfo, true, tool, "path-seg[" + si + "]-main" + layerTag);
                            if (!params.isEmpty()) harvestAndTry(params, messageInfo, true, tool, "path-seg[" + si + "]-semiparams" + layerTag);
                        }
                    }
                }
            }
        }

        // PARAMETERS via Burp (works across methods: GET/POST/PUT/…)
        for (IParameter p : req.getParameters()) {
            String v = p.getValue();
            if (v == null || v.isEmpty()) continue;

            int t = p.getType();
            String kind = (t == IParameter.PARAM_URL) ? "param-url:" + p.getName()
                    : (t == IParameter.PARAM_BODY) ? "param-body:" + p.getName()
                    : "param-" + t + ":" + p.getName();

            for (String vLayer : urlDecodeChain3(v)) {
                harvestAndTry(vLayer, messageInfo, true, tool, kind);
            }
        }

        // RAW QUERY (entire query string)
        String q = url.getQuery();
        if (q != null && !q.isEmpty()) {
            for (String qLayer : urlDecodeChain3(q)) {
                harvestAndTry(qLayer, messageInfo, true, tool, "query");
            }
        }

        // HEADERS (skip noisy), but allow minimal decode of values
        for (String h : req.getHeaders()) {
            int idx = h.indexOf(':');
            if (idx < 0) continue;
            String name = h.substring(0, idx).trim();
            String val  = h.substring(idx + 1).trim();

            String lname = name.toLowerCase(Locale.ROOT);
            if (lname.equals("cookie") || lname.equals("set-cookie") || lname.equals("authorization")) continue;
            if (lname.startsWith("accept-") || lname.equals("user-agent") || lname.equals("referer") ||
                lname.equals("sec-fetch-site") || lname.equals("sec-fetch-mode") || lname.equals("sec-fetch-user") ||
                lname.equals("sec-fetch-dest") || lname.equals("cache-control") || lname.equals("accept-language") ||
                lname.equals("accept-encoding") || lname.equals("priority")) {
                continue;
            }
            for (String vLayer : urlDecodeChain2(val)) {
                harvestAndTry(vLayer, messageInfo, true, tool, "header:" + name);
            }
        }

        // BODY (as text; param extraction above already covers key/vals for known types)
        byte[] body = Arrays.copyOfRange(messageInfo.getRequest(), req.getBodyOffset(), messageInfo.getRequest().length);
        if (body.length > 0) {
            String bodyStr = new String(body, StandardCharsets.UTF_8);
            for (String bLayer : urlDecodeChain3(bodyStr)) {
                harvestAndTry(bLayer, messageInfo, true, tool, "body");
            }
        }
    }

    // ===================== URL decode chains =====================

    /** Decode up to `max` times; stop early when decoding no longer changes the string. */
    private List<String> urlDecodeChain(String s, int max) {
        ArrayList<String> layers = new ArrayList<>(max + 1);
        if (s == null) return layers;
        String prev = s;
        layers.add(prev);
        for (int i = 0; i < max; i++) {
            String dec = urlDecode(prev);
            if (dec.equals(prev)) break;     // stable -> stop
            layers.add(dec);
            prev = dec;
        }
        // Deduplicate while preserving order
        LinkedHashSet<String> uniq = new LinkedHashSet<>(layers);
        return new ArrayList<>(uniq);
    }
    private List<String> urlDecodeChain2(String s) { return urlDecodeChain(s, 2); }
    private List<String> urlDecodeChain3(String s) { return urlDecodeChain(s, 3); }

    private String urlDecode(String s) { try { return helpers.urlDecode(s); } catch (Exception e) { return s; } }

    // ===================== Core harvest/try =====================

    /** Canonical-first decode/scan across multiple URL-decoded layers (raw, dec1, dec2...). */
    private void harvestAndTry(String s, IHttpRequestResponse msg, boolean isReq, String tool, String origin) {
        if (s == null || s.isEmpty()) return;

        // Build layers: raw -> dec1 -> dec2 (no duplicates)
        List<String> layers = urlDecodeChain3(s);

        // ---- FAST PATH EU on each layer (canonical-first) ----
        for (int i = 0; i < layers.size(); i++) {
            String layer = layers.get(i);
            if (!looksLikeEU(layer)) continue;
            String out = tryEU(layer);
            if (accept(out)) {
                String tag = origin + (i == 0 ? "-EU-fast" : "-EU-fast-dec" + i);
                recordResult(msg, isReq, tool, layer, out, tag);
                return;
            }
        }

        // ---- FALLBACK: token harvesting on each layer ----
        for (int i = 0; i < layers.size(); i++) {
            String layer = layers.get(i);
            if (layer == null || layer.isEmpty()) continue;

            Matcher m = CANDIDATE.matcher(layer);
            while (m.find()) {
                String cand = m.group();
                if (cand.length() < MIN_TOKEN_LEN) continue;

                String res = null;
                if (looksLikeEU(cand)) {
                    res = tryEU(cand);
                    if (!accept(res) && BASE64ISH.matcher(cand).matches()) res = tryB64(cand);
                } else if (BASE64ISH.matcher(cand).matches()) {
                    res = tryB64(cand);
                    if (!accept(res) && looksLikeEU(cand)) res = tryEU(cand);
                } else {
                    res = tryUTF16(cand);
                }

                if (accept(res)) {
                    String tag = origin + (i == 0 ? "" : "-dec" + i);
                    recordResult(msg, isReq, tool, cand, res, tag);
                    return; // one hit per origin is enough
                }
            }
        }
    }

    // ===================== Decode routes =====================
    private String tryEU(String s) {
        try {
            String out = LZStringJava.decompressFromEncodedURIComponent(s);
            if (logAllAttempts && out == null) stdout.println("[EU] no (" + shorten(s) + ")");
            return postprocess(out);
        } catch (Throwable t) {
            if (logAllAttempts) stdout.println("[EU] err " + t);
            return null;
        }
    }

    private String tryB64(String s) {
        try {
            String out = LZStringJava.decompressFromBase64(normalizeBase64(s));
            if (logAllAttempts && out == null) stdout.println("[B64] no (" + shorten(s) + ")");
            return postprocess(out);
        } catch (Throwable t) {
            if (logAllAttempts) stdout.println("[B64] err " + t);
            return null;
        }
    }

    private String tryUTF16(String s) {
        try {
            String out = LZStringJava.decompressFromUTF16(s);
            if (logAllAttempts && out == null) stdout.println("[UTF16] no (" + shorten(s) + ")");
            return postprocess(out);
        } catch (Throwable t) {
            if (logAllAttempts) stdout.println("[UTF16] err " + t);
            return null;
        }
    }

    // ===================== Heuristics / helpers =====================
    private boolean looksLikeEU(String s) {
        if (s == null || s.length() < MIN_TOKEN_LEN) return false;
        int ok = 0, bad = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (EU_ALPHA.indexOf(c) >= 0) ok++;
            else if (c == '-' || c == '_' || c == '.' ) ok++; // permissive runes in path
            else bad++;
        }
        double ratio = (ok * 1.0 / s.length());
        return ratio >= (strictMode ? 0.95 : 0.85);
    }

    private boolean accept(String decoded) {
        if (decoded == null) return false;
        if (decoded.length() > MAX_DECODE_LEN) return false;
        if (!passesQuality(decoded)) return false;
        return !readableOnly || isReadable(decoded);
    }

    private String postprocess(String s) {
        if (s == null) return null;
        if (s.isEmpty()) return "";
        // If it decodes to bytes mistakenly mapped as ISO-8859-1, try UTF-8 reinterpret
        if (!looksMostlyUtf8(s)) {
            try {
                byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
                String t = new String(b, StandardCharsets.UTF_8);
                s = t;
            } catch (Exception ignored) {}
        }
        return s;
    }

    private boolean looksMostlyUtf8(String s) {
        // Heuristic: presence of replacement char suggests broken encoding
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '\uFFFD') return false;
        return true;
    }

    /** Stronger quality gate than plain "readable". */
    private boolean passesQuality(String s) {
        int len = s.length();
        if (len == 0) return false;

        int printable = 0, control = 0, ascii = 0;
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c >= 32 && c <= 126 || c == '\t' || c == '\n' || c == '\r') printable++;
            if (c < 32 && c != '\t' && c != '\n' && c != '\r') control++;
            if (c <= 0x7F) ascii++;
        }

        double printableRatio = printable * 1.0 / len;
        double asciiRatio     = ascii * 1.0 / len;
        double controlRatio   = control * 1.0 / len;

        if (strictMode) {
            if (printableRatio < 0.90) return false;
            if (asciiRatio     < 0.85) return false;
            if (controlRatio   > 0.01) return false;
        } else {
            if (printableRatio < 0.80) return false;
            if (asciiRatio     < 0.70) return false;
            if (controlRatio   > 0.03) return false;
        }

        // Structure hints (not required, just helpful)
        if (looksStructured(s)) return true;

        // For generic blobs, require a bit more printable content
        return printableRatio >= (strictMode ? 0.94 : 0.86);
    }

    private boolean looksStructured(String s) {
        String t = s.trim();
        // JSON-like
        if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
            int bal = 0;
            for (int i = 0; i < t.length(); i++) {
                char c = t.charAt(i);
                if (c == '{') bal++;
                else if (c == '}') bal--;
                if (bal < -2) return false;
            }
            return true;
        }
        // Quick signals: URL-ish / key:value-ish / email-ish
        if (t.startsWith("http://") || t.startsWith("https://")) return true;
        if (t.indexOf(':') > 0 && t.indexOf(',') > 0) return true;
        if (t.indexOf('@') > 0 && t.indexOf('.', t.indexOf('@')) > t.indexOf('@')) return true;
        return false;
    }

    /** Legacy readable gate used with readableOnly toggle. */
    private boolean isReadable(String s) {
        int total = s.length(), printable = 0, control = 0;
        for (int i = 0; i < total; i++) {
            char c = s.charAt(i);
            if (c >= 32 && c <= 126 || c == '\t' || c == '\n' || c == '\r') printable++;
            else if (c < 32) control++;
        }
        return control <= total * 0.05 && printable >= total * 0.70;
    }

    private void recordResult(IHttpRequestResponse msg, boolean isReq, String tool, String token, String decoded, String origin) {
        DecodeResult r = new DecodeResult(
                System.currentTimeMillis(),
                isReq,
                helpers.analyzeRequest(msg).getUrl().getHost(),
                helpers.analyzeRequest(msg).getUrl().getPort(),
                tool,
                origin,
                token.length(),
                token,
                decoded,
                msg
        );
        results.add(r);
        SwingUtilities.invokeLater(() -> tableModel.fireTableDataChanged());
        saveToFile(r);
        stdout.println("[LZString] hit@" + origin + " -> " + shorten(decoded));
    }

    private void saveToFile(DecodeResult r) {
        try {
            String t = new SimpleDateFormat("yyyyMMdd'T'HHmmss").format(new Date(r.time));
            String fn = String.format("%s_%s_%d_%s.txt", t, r.host.replace(":", "_"), r.port, r.isRequest ? "req" : "resp");
            File f = new File(SAVE_DIR, fn.replaceAll("[^a-zA-Z0-9._-]", "_"));
            try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8))) {
                pw.println("Time: " + t);
                pw.println("Host: " + r.host);
                pw.println("Port: " + r.port);
                pw.println("Origin: " + r.origin);
                pw.println("TokenLen: " + r.tokenLen);
                pw.println("\n--- Decoded ---\n" + r.decoded);
                pw.println("\n--- Token ---\n" + r.token);
            }
        } catch (Exception e) { stderr.println("Save error: " + e); }
    }

    private void createIssues() {
        int cnt = 0;
        for (DecodeResult r : results) {
            try {
                String detail = "<b>Origin:</b> " + r.origin +
                        "<br><b>Token:</b> <pre>" + escape(r.token) + "</pre>" +
                        "<br><b>Decoded:</b> <pre>" + escape(r.decoded) + "</pre>";
                IScanIssue issue = new CustomScanIssue(
                        r.messageInfo.getHttpService(),
                        helpers.analyzeRequest(r.messageInfo).getUrl(),
                        new IHttpRequestResponse[]{r.messageInfo},
                        "LZString Detected",
                        detail,
                        "Information"
                );
                callbacks.addScanIssue(issue);
                cnt++;
            } catch (Exception ignored) {}
        }
        JOptionPane.showMessageDialog(panel, "Created " + cnt + " issue(s).");
    }

    private void exportToZip() {
        JFileChooser fc = new JFileChooser(SAVE_DIR);
        if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        String path = fc.getSelectedFile().getAbsolutePath();
        if (!path.endsWith(".zip")) path += ".zip";
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(path))) {
            int idx = 0;
            for (DecodeResult r : results) {
                if (r.decoded.isEmpty()) continue;
                idx++;
                String name = String.format("%03d_%s_%s_%d.txt", idx, r.host.replace(":", "_"), r.port, r.isRequest ? "req" : "resp");
                zos.putNextEntry(new ZipEntry(name));
                zos.write(("Origin: " + r.origin + "\n\n--- Decoded ---\n" + r.decoded + "\n\n--- Token ---\n" + r.token).getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
            JOptionPane.showMessageDialog(panel, "Exported to:\n" + path);
        } catch (Exception e) { stderr.println("ZIP error: " + e); }
    }

    private void testManualDecode() {
        String in = JOptionPane.showInputDialog(panel, "Enter token to decode:");
        if (in == null || in.trim().isEmpty()) return;
        String out = tryEU(in.trim());
        if (!accept(out)) out = tryB64(in.trim());
        if (!accept(out)) out = tryUTF16(in.trim());
        JTextArea ta = new JTextArea(out != null ? out : "No decode", 20, 80);
        ta.setEditable(false);
        JOptionPane.showMessageDialog(panel, new JScrollPane(ta), "Decode Result", JOptionPane.PLAIN_MESSAGE);
    }

    private void showDetailDialog(DecodeResult r) {
        JDialog d = new JDialog((Frame) null, "LZString – Details", true);
        d.setLayout(new BorderLayout());

        JTextArea taDecoded = new JTextArea(r.decoded, 24, 80);
        taDecoded.setEditable(false);

        JTextArea taToken = new JTextArea(r.token, 24, 60);
        taToken.setEditable(false);

        JScrollPane spDecoded = new JScrollPane(taDecoded);
        spDecoded.setBorder(BorderFactory.createTitledBorder("Decoded"));

        JScrollPane spToken = new JScrollPane(taToken);
        spToken.setBorder(BorderFactory.createTitledBorder("Token (raw)"));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, spDecoded, spToken);
        split.setResizeWeight(0.65); // favor decoded pane
        d.add(split, BorderLayout.CENTER);

        JPanel footer = new JPanel(new GridLayout(2, 1));
        JLabel lbl1 = new JLabel("Origin: " + r.origin + "    Host: " + r.host + ":" + r.port);
        JLabel lbl2 = new JLabel("Tool: " + r.tool + "    Token length: " + r.tokenLen + "    Type: " + (r.isRequest ? "Request" : "Response"));
        footer.add(lbl1);
        footer.add(lbl2);
        d.add(footer, BorderLayout.SOUTH);

        d.pack();
        d.setLocationRelativeTo(panel);
        d.setVisible(true);
    }

    private String normalizeBase64(String s) {
        String t = s.replace('-', '+').replace('_', '/');
        int p = t.length() % 4;
        if (p > 0) t += "===".substring(0, 4 - p);
        return t;
    }

    private String escape(String s) { return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"); }
    private String shorten(String s) { return (s == null) ? "null" : (s.length() > 80 ? s.substring(0, 77) + "..." : s); }

    // ===================== Table / DTO / Issue =====================
    private class ResultsTableModel extends AbstractTableModel {
        // Added a "Token" column (pre-decoded/matched layer) and "Decoded".
        private final String[] cols = {"#", "Type", "Host", "Port", "Tool", "Origin", "Len", "Token", "Decoded"};

        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int c) { return cols[c]; }

        @Override public Object getValueAt(int r, int c) {
            DecodeResult dr = results.get(r);
            switch (c) {
                case 0: return r + 1;
                case 1: return dr.isRequest ? "Req" : "Resp";
                case 2: return dr.host;
                case 3: return dr.port;
                case 4: return dr.tool;
                case 5: return dr.origin;
                case 6: return dr.tokenLen;
                case 7: return dr.token.length() > 50 ? dr.token.substring(0, 47) + "..." : dr.token; // Token preview
                case 8: return dr.decoded.length() > 50 ? dr.decoded.substring(0, 47) + "..." : dr.decoded; // Decoded preview
                default: return "";
            }
        }
    }

    private static class DecodeResult {
        final long time; final boolean isRequest; final String host; final int port;
        final String tool; final String origin; final int tokenLen;
        final String token; final String decoded; final IHttpRequestResponse messageInfo;

        DecodeResult(long t, boolean ir, String h, int p, String tl, String o, int tl2,
                     String tk, String dc, IHttpRequestResponse mi) {
            time = t; isRequest = ir; host = h; port = p; tool = tl; origin = o;
            tokenLen = tl2; token = tk; decoded = dc; messageInfo = mi;
        }
    }

    private static class CustomScanIssue implements IScanIssue {
        private final IHttpService svc;
        private final URL url;
        private final IHttpRequestResponse[] msgs;
        private final String name, detail, severity;

        CustomScanIssue(IHttpService s, URL u, IHttpRequestResponse[] m,
                        String n, String d, String sev) {
            svc = s; url = u; msgs = m; name = n; detail = d; severity = sev;
        }
        @Override public URL getUrl() { return url; }
        @Override public String getIssueName() { return name; }
        @Override public int getIssueType() { return 0; }
        @Override public String getSeverity() { return severity; }
        @Override public String getConfidence() { return "Certain"; }
        @Override public String getIssueBackground() { return null; }
        @Override public String getRemediationBackground() { return null; }
        @Override public String getIssueDetail() { return detail; }
        @Override public String getRemediationDetail() { return null; }
        @Override public IHttpRequestResponse[] getHttpMessages() { return msgs; }
        @Override public IHttpService getHttpService() { return svc; }
        @Override public String getProtocol() { return url.getProtocol(); }
        @Override public int getPort() { return url.getPort() == -1 ? url.getDefaultPort() : url.getPort(); }
        @Override public String getHost() { return url.getHost(); }
    }
}

/* ==========================
 * Known-good pure-Java LZString port
 * (decompressFromBase64 / EncodedURIComponent / UTF16)
 * ========================== */
class LZStringJava {
    private static final String BASE64_ALPHABET   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final String URI_SAFE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$";

    public static String decompressFromBase64(String input) {
        if (input == null) return null;
        final String s = input; // effectively final for lambda
        return decompress(s.length(), 32, idx -> getBaseValue(BASE64_ALPHABET, s.charAt(idx)));
    }

    public static String decompressFromEncodedURIComponent(String input) {
        if (input == null) return null;
        final String s = input.replace(" ", "+"); // parity with JS impl
        return decompress(s.length(), 32, idx -> getBaseValue(URI_SAFE_ALPHABET, s.charAt(idx)));
    }

    public static String decompressFromUTF16(String input) {
        if (input == null) return null;
        final String s = input;
        return decompress(s.length(), 16384, idx -> ((int) s.charAt(idx)) - 32);
    }

    // ---------- Core ----------
    private interface CharProvider { int at(int index); }

    private static String decompress(int length, int resetValue, CharProvider getBase) {
        List<String> dictionary = new ArrayList<>(4096);
        int enlargeIn = 4;
        int dictSize  = 4;
        int numBits   = 3;
        String entry;
        StringBuilder result = new StringBuilder();

        Data data = new Data(1, getBase.at(0), resetValue);

        // Base dictionary placeholders (0,1,2)
        for (int i = 0; i < 3; i++) dictionary.add(null);

        int next = readBits(data, 2, getBase, length);
        if (next == 2) return "";

        int c;
        if (next == 0) c = readBits(data, 8, getBase, length);
        else if (next == 1) c = readBits(data, 16, getBase, length);
        else return null;

        String w = "" + (char) c;
        dictionary.add(w);
        result.append(w);

        while (true) {
            int cc = readBits(data, numBits, getBase, length);
            if (cc == -1) break;

            if (cc == 0) {
                c = readBits(data, 8, getBase, length);
                dictionary.add("" + (char)c);
                cc = dictSize++;
                enlargeIn--;
            } else if (cc == 1) {
                c = readBits(data, 16, getBase, length);
                dictionary.add("" + (char)c);
                cc = dictSize++;
                enlargeIn--;
            } else if (cc == 2) {
                return result.toString();
            }

            if (enlargeIn == 0) { enlargeIn = 1 << numBits; numBits++; }

            if (cc < dictionary.size() && dictionary.get(cc) != null) {
                entry = dictionary.get(cc);
            } else if (cc == dictSize) {
                entry = w + w.charAt(0);
            } else {
                return null;
            }

            result.append(entry);
            dictionary.add(w + entry.charAt(0));
            dictSize++;
            enlargeIn--;

            w = entry;

            if (enlargeIn == 0) { enlargeIn = 1 << numBits; numBits++; }
        }
        return null; // invalid/unfinished stream
    }

    private static int getBaseValue(String alphabet, char character) {
        int p = alphabet.indexOf(character);
        return (p >= 0) ? p : 0; // clamp unknown like JS
    }

    private static int readBits(Data data, int n, CharProvider getBase, int length) {
        int res = 0;
        int maxpower = 1 << n;
        int power = 1;
        while (power != maxpower) {
            int bit = data.val & data.position;
            data.position >>= 1;
            if (data.position == 0) {
                data.position = data.resetValue;
                if (data.index >= length) return -1;
                data.val = getBase.at(data.index++);
            }
            if (bit != 0) res |= power;
            power <<= 1;
        }
        return res;
    }

    private static class Data {
        int index;
        int val;
        int position;
        int resetValue;

        Data(int index, int firstVal, int resetValue) {
            this.index = index;
            this.val = firstVal;
            this.position = resetValue;
            this.resetValue = resetValue;
        }
    }
}
