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
import java.util.zip.*;

/**
 * DecoderDetectorV2 — patched (v3)
 * Ensures isLikelyBase64Token(...) exists inside the class.
 */
public class DecoderDetectorV2 implements IBurpExtender, IHttpListener, ITab {

    // === Burp interfaces ===
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    // === Tunables / Patterns ===
    private static final int MIN_TOKEN_LEN        = 8;
    private static final int MIN_TOKEN_LEN_B64    = 8;
    private static final int MAX_DECODE_LEN       = 16384;
    private static final String SAVE_DIR = System.getProperty("user.home")
            + File.separator + "burp-outputs" + File.separator + "decoder_detector_v2";

    private static final String EU_ALPHA  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$";
    private static final Pattern CANDIDATE =
            Pattern.compile("[A-Za-z0-9_\\-\\+\\$/=\\.]{"+ MIN_TOKEN_LEN +",}");
    private static final Pattern BASE64ISH =
            Pattern.compile("^[A-Za-z0-9_\\-+/=]{"+ MIN_TOKEN_LEN_B64 +",}$");

    // === Options ===
    private boolean scopeOnly      = true;
    private boolean readableOnly   = true;
    private boolean strictMode     = true;
    private boolean logAllAttempts = false;

    // === UI ===
    private JPanel panel;
    private JTable resultsTable;
    private ResultsTableModel tableModel;
    private final java.util.List<DecodeResult> results = new ArrayList<>();

    // ================= IBurpExtender =================
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
        this.callbacks = cb;
        this.helpers   = cb.getHelpers();
        this.stdout    = new PrintWriter(cb.getStdout(), true);
        this.stderr    = new PrintWriter(cb.getStderr(), true);

        cb.setExtensionName("DecoderDetectorV2");
        cb.registerHttpListener(this);
        new File(SAVE_DIR).mkdirs();
        buildUI();
        cb.addSuiteTab(this);

        stdout.println("[DecoderDetectorV2] Loaded.");
    }

    // ================= ITab =================
    @Override public String getTabCaption() { return "DecoderDetectorV2"; }
    @Override public Component getUiComponent() { return panel; }

    // ================= IHttpListener =================
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
            final String tool = callbacks.getToolName(toolFlag);

            if (messageIsRequest) {
                IRequestInfo req = helpers.analyzeRequest(messageInfo);
                if (scopeOnly && !callbacks.isInScope(req.getUrl())) return;

                final URL url = req.getUrl();

                // PATH split + decode layers
                String path = url.getPath();
                if (path != null && !path.isEmpty()) {
                    for (String layer : urlDecodeChain(path, 3)) {
                        String trimmed = trimSlashes(layer);
                        if (trimmed.isEmpty()) continue;
                        String[] segs = trimmed.split("/");
                        for (int i = 0; i < segs.length; i++) {
                            String seg = segs[i];
                            if (seg.isEmpty()) continue;
                            for (String segLayer : urlDecodeChain(seg, 2)) {
                                harvestAndTry(segLayer, messageInfo, true, tool, "path-seg[" + i + "]");
                            }
                        }
                    }
                }

                // PARAMETERS (Burp)
                for (IParameter p : req.getParameters()) {
                    String v = p.getValue();
                    if (v == null || v.isEmpty()) continue;
                    int t = p.getType();
                    String kind = (t == IParameter.PARAM_URL) ? "param-url:" + p.getName()
                            : (t == IParameter.PARAM_BODY) ? "param-body:" + p.getName()
                            : "param-" + t + ":" + p.getName();
                    for (String vLayer : urlDecodeChain(v, 3)) {
                        harvestAndTry(vLayer, messageInfo, true, tool, kind);
                    }
                }

                // RAW query key=value scanning (exact substring after '=')
                String rawQuery = url.getQuery();
                if (rawQuery != null && !rawQuery.isEmpty()) {
                    for (String pair : rawQuery.split("&")) {
                        if (pair == null || pair.isEmpty()) continue;
                        int eq = pair.indexOf('=');
                        if (eq < 0) continue;
                        String rawVal = pair.substring(eq + 1);
                        for (String vLayer : urlDecodeChain(rawVal, 3)) {
                            harvestAndTry(vLayer, messageInfo, true, tool, "raw-query:" + (pair.length()>0?pair.substring(0, Math.min(20,pair.length())):""));
                        }
                    }
                }

                // Entire raw QUERY (as a whole)
                String q = url.getQuery();
                if (q != null && !q.isEmpty()) {
                    for (String qLayer : urlDecodeChain(q, 3)) {
                        harvestAndTry(qLayer, messageInfo, true, tool, "query");
                    }
                }

                // HEADERS (filtered)
                List<String> headers = req.getHeaders();
                for (String h : headers) {
                    int idx = h.indexOf(':');
                    if (idx < 0) continue;
                    String name = h.substring(0, idx).trim();
                    String val  = h.substring(idx + 1).trim();

                    String lname = name.toLowerCase(Locale.ROOT);
                    if (lname.equals("cookie") || lname.equals("set-cookie") || lname.equals("authorization")) continue;
                    if (lname.startsWith("accept-") || lname.equals("user-agent") || lname.equals("referer") ||
                        lname.startsWith("sec-fetch") || lname.equals("cache-control") ||
                        lname.equals("accept-language") || lname.equals("accept-encoding") || lname.equals("priority")) {
                        continue;
                    }
                    for (String vLayer : urlDecodeChain(val, 2)) {
                        harvestAndTry(vLayer, messageInfo, true, tool, "header:" + name);
                    }
                }

                // BODY (text)
                byte[] reqBytes = messageInfo.getRequest();
                int off = req.getBodyOffset();
                if (off < reqBytes.length) {
                    String body = new String(Arrays.copyOfRange(reqBytes, off, reqBytes.length), StandardCharsets.UTF_8);
                    if (isAllowedContentType(getHeaderValue(req.getHeaders(), "Content-Type"))) {
                        for (String bLayer : urlDecodeChain(body, 3)) {
                            harvestAndTry(bLayer, messageInfo, true, tool, "body");
                        }
                    }
                }

            } else {
                // RESPONSE side scanning (content-type gating)
                IResponseInfo resp = helpers.analyzeResponse(messageInfo.getResponse());
                List<String> rh = resp.getHeaders();
                String ct = getHeaderValue(rh, "Content-Type");
                if (!isAllowedContentType(ct)) return;

                int boff = resp.getBodyOffset();
                byte[] respBytes = messageInfo.getResponse();
                if (boff < respBytes.length) {
                    String body = new String(Arrays.copyOfRange(respBytes, boff, respBytes.length), StandardCharsets.UTF_8);
                    for (String bLayer : urlDecodeChain(body, 3)) {
                        harvestAndTry(bLayer, messageInfo, false, tool, "resp-body");
                    }
                }
            }

        } catch (Throwable t) {
            if (stderr != null) stderr.println("[DecoderDetectorV2] Error: " + t);
        }
    }

    // ================= UI =================
    private void buildUI() {
        panel = new JPanel(new BorderLayout());

        JPanel top = new JPanel(new GridLayout(1, 10));
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

        JButton btnMake = new JButton("Make Token");
        btnMake.addActionListener(e -> makeTokenDialog());
        top.add(btnMake);

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

    // Table / DTO
    private class ResultsTableModel extends AbstractTableModel {
        private final String[] cols = {"#", "Type", "Host", "Port", "Tool", "Origin", "Len", "Token", "Decoded"};
        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int c) { return cols[c]; }
        @Override public Object getValueAt(int r, int c) {
            DecodeResult dr = results.get(r);
            switch (c) {
                case 0: return r + 1;
                case 1: return dr.isRequest ? "Request" : "Response";
                case 2: return dr.host;
                case 3: return dr.port;
                case 4: return dr.tool;
                case 5: return dr.origin;
                case 6: return dr.tokenLen;
                case 7: return dr.token.length() > 50 ? dr.token.substring(0, 47) + "..." : dr.token;
                case 8: return dr.decoded.length() > 50 ? dr.decoded.substring(0, 47) + "..." : dr.decoded;
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

    private void showDetailDialog(DecodeResult r) {
        JDialog d = new JDialog((Frame) null, "DecoderDetectorV2 – Details", true);
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
        split.setResizeWeight(0.65);
        d.add(split, BorderLayout.CENTER);

        JPanel footer = new JPanel(new GridLayout(2, 1));
        JLabel lbl1 = new JLabel("Origin: " + r.origin + "    Host: " + r.host + ":" + r.port);
        JLabel lbl2 = new JLabel("Tool: " + r.tool + "    Token length: " + r.tokenLen + "    Type: " + (r.isRequest ? "Request" : "Response"));
        footer.add(lbl1); footer.add(lbl2);
        d.add(footer, BorderLayout.SOUTH);

        d.pack();
        d.setLocationRelativeTo(panel);
        d.setVisible(true);
    }

    // ================= URL decode chains =================
    private List<String> urlDecodeChain(String s, int max) {
        ArrayList<String> layers = new ArrayList<>(max + 1);
        if (s == null) return layers;
        String prev = s;
        layers.add(prev);
        for (int i = 0; i < max; i++) {
            String dec = urlDecode(prev);
            if (dec.equals(prev)) break;
            layers.add(dec);
            prev = dec;
        }
        LinkedHashSet<String> uniq = new LinkedHashSet<>(layers);
        return new ArrayList<>(uniq);
    }
    private String urlDecode(String s) { try { return helpers.urlDecode(s); } catch (Exception e) { return s; } }
    private String trimSlashes(String s) {
        String t = s;
        if (t.startsWith("/")) t = t.substring(1);
        if (t.endsWith("/")) t = t.substring(0, t.length() - 1);
        return t;
    }

    // ================= Harvest / Try =================
    private void harvestAndTry(String s, IHttpRequestResponse msg, boolean isReq, String tool, String origin) {
        if (s == null || s.isEmpty()) return;

        if (logAllAttempts && stdout != null) stdout.println("[DBG harvest] origin=" + origin + " len=" + s.length() + " snippet=" + (s.length()>80? s.substring(0,80)+"..." : s));

        // Fast path EU on each layer
        for (String layer : urlDecodeChain(s, 3)) {
            if (looksLikeEU(layer)) {
                String out = tryEU(layer);
                if (accept(out)) { recordResult(msg, isReq, tool, layer, out, origin + "-EU-fast"); return; }
            }
        }
        // Fallback token harvesting
        for (String layer : urlDecodeChain(s, 3)) {
            Matcher m = CANDIDATE.matcher(layer);
            while (m.find()) {
                String cand = m.group();
                if (cand.length() < MIN_TOKEN_LEN) continue;
                String res = null;
                // prefer base64-like tokens first
                if (isLikelyBase64Token(cand)) {
                    res = tryB64(cand);
                    if (!accept(res) && looksLikeEU(cand)) res = tryEU(cand);
                    if (!accept(res)) res = tryUTF16(cand);
                } else if (looksLikeEU(cand)) {
                    res = tryEU(cand);
                    if (!accept(res) && BASE64ISH.matcher(cand).matches()) res = tryB64(cand);
                } else if (BASE64ISH.matcher(cand).matches()) {
                    res = tryB64(cand);
                    if (!accept(res) && looksLikeEU(cand)) res = tryEU(cand);
                } else {
                    res = tryUTF16(cand);
                }

                if (accept(res)) {
                    recordResult(msg, isReq, tool, cand, res, origin);
                    return;
                }
            }
        }
    }

    // Heuristic: base64-ish with padding sanity.
    private boolean isLikelyBase64Token(String s) {
        if (s == null) return false;
        String t = s.trim();
        if (t.length() < MIN_TOKEN_LEN_B64) return false;
        if (!BASE64ISH.matcher(t).matches()) return false;
        int firstEq = t.indexOf('=');
        if (firstEq >= 0) {
            for (int i = firstEq; i < t.length(); i++) if (t.charAt(i) != '=') return false;
            String norm = normalizeBase64(t);
            if ((norm.length() % 4) != 0) return false;
        }
        return true;
    }

    // ================= Decode routes (wrappers) =================
    private String tryEU(String s) {
        try {
            String out = LZStringJava.decompressFromEncodedURIComponent(s);
            if (logAllAttempts && out == null) stdout.println("[EU] no (" + shorten(s) + ")");
            return postprocess(out);
        } catch (Throwable t) { if (logAllAttempts) stdout.println("[EU] err " + t); return null; }
    }
    private String tryB64(String s) {
        try {
            byte[] b = tryBase64(s);
            if (b == null) return null;
            // try LZString first then raw txt variants
            String lz = LZStringJava.decompressFromBase64(normalizeBase64(s));
            if (lz != null && !lz.isEmpty()) return postprocess(lz);
            String txt = bytesToUtf8IfHuman(b);
            if (txt != null && !txt.isEmpty()) return postprocess(txt);
            // try gzip/zlib/deflate/brotli/lz4/zstd/snappy as bytes
            String gz = tryGzip(b); if (accept(gz)) return gz;
            String zl = tryZlib(b,false); if (accept(zl)) return zl;
            String df = tryZlib(b,true); if (accept(df)) return df;
            String br = tryViaReflectStream("org.brotli.dec.BrotliInputStream", b); if (accept(br)) return br;
            String lz4= tryViaReflectStream("net.jpountz.lz4.LZ4FrameInputStream", b); if (accept(lz4)) return lz4;
            String zs = tryViaReflectStream("com.github.luben.zstd.ZstdInputStream", b); if (accept(zs)) return zs;
            String sn = tryViaReflectStream("org.xerial.snappy.SnappyInputStream", b); if (accept(sn)) return sn;
            return null;
        } catch (Throwable t) { if (logAllAttempts) stdout.println("[B64] err " + t); return null; }
    }
    private String tryUTF16(String s) {
        try {
            String out = LZStringJava.decompressFromUTF16(s);
            if (logAllAttempts && out == null) stdout.println("[UTF16] no (" + shorten(s) + ")");
            return postprocess(out);
        } catch (Throwable t) { if (logAllAttempts) stdout.println("[UTF16] err " + t); return null; }
    }

    // ================= Misc helpers =================
    private boolean looksLikeEU(String s) {
        if (s == null || s.length() < MIN_TOKEN_LEN) return false;
        int ok = 0, bad = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (EU_ALPHA.indexOf(c) >= 0) ok++;
            else if (c == '-' || c == '_' || c == '.' ) ok++;
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
        String t = s.trim();
        if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) return true;
        if (t.startsWith("http://") || t.startsWith("https://")) return true;
        if (t.indexOf(':') > 0 && t.indexOf(',') > 0) return true;
        if (t.indexOf('@') > 0 && t.indexOf('.', t.indexOf('@')) > t.indexOf('@')) return true;
        return printableRatio >= (strictMode ? 0.94 : 0.86);
    }
    private boolean isReadable(String s) {
        int total = s.length(), printable = 0, control = 0;
        for (int i = 0; i < total; i++) {
            char c = s.charAt(i);
            if (c >= 32 && c <= 126 || c == '\t' || c == '\n' || c == '\r') printable++;
            else if (c < 32) control++;
        }
        return control <= total * 0.05 && printable >= total * 0.70;
    }
    private String postprocess(String s) {
        if (s == null) return null;
        if (s.isEmpty()) return "";
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '\uFFFD') {
            try {
                byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
                String t = new String(b, StandardCharsets.UTF_8);
                s = t;
            } catch (Exception ignored) {}
            break;
        }
        return s;
    }
    private String normalizeBase64(String s) {
        String t = s.replace('-', '+').replace('_', '/');
        int p = t.length() % 4;
        if (p > 0) t += "===".substring(0, 4 - p);
        return t;
    }
    private String shorten(String s) { return (s == null) ? "null" : (s.length() > 80 ? s.substring(0, 77) + "..." : s); }
    private String escape(String s) { return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"); }

    private void recordResult(IHttpRequestResponse msg, boolean isReq, String tool, String token, String decoded, String origin) {
        IRequestInfo ri = helpers.analyzeRequest(msg);
        DecodeResult r = new DecodeResult(
                System.currentTimeMillis(),
                isReq,
                ri.getUrl().getHost(),
                ri.getUrl().getPort(),
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
        stdout.println("[Decoder] hit@" + origin + " -> " + shorten(decoded));
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
                        "DecoderDetectorV2 Finding",
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
                String name = String.format("%03d_%s_%s_%d.txt", idx, r.host.replace(":", "_"), r.isRequest ? "req" : "resp", r.port);
                zos.putNextEntry(new ZipEntry(name));
                zos.write(("Origin: " + r.origin + "\n\n--- Decoded ---\n" + r.decoded + "\n\n--- Token ---\n" + r.token).getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
            JOptionPane.showMessageDialog(panel, "Exported to:\n" + path);
        } catch (Exception e) { stderr.println("ZIP error: " + e); }
    }

    // ================= Grid UI helpers + dialogs =================
    private static class KVTableModel extends AbstractTableModel {
        private final String[] cols = {"Variant", "Value"};
        private final java.util.List<String[]> rows;
        KVTableModel(java.util.List<String[]> rows) { this.rows = rows; }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return 2; }
        @Override public String getColumnName(int c) { return cols[c]; }
        @Override public Object getValueAt(int r, int c) { return rows.get(r)[c]; }
        public String getAllAsText() {
            StringBuilder sb = new StringBuilder();
            for (String[] r : rows) sb.append("[").append(r[0]).append("]\n").append(r[1]).append("\n\n");
            return sb.toString();
        }
    }
    private static class TextAreaRenderer extends JTextArea implements javax.swing.table.TableCellRenderer {
        TextAreaRenderer() {
            setLineWrap(true); setWrapStyleWord(true);
            setOpaque(true); setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        }
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            setText(value == null ? "" : value.toString());
            setCaretPosition(0);
            if (isSelected) {
                setBackground(table.getSelectionBackground());
                setForeground(table.getSelectionForeground());
            } else {
                setBackground(table.getBackground());
                setForeground(table.getForeground());
            }
            int w = table.getColumnModel().getColumn(column).getWidth();
            setSize(new Dimension(w, Short.MAX_VALUE));
            int h = getPreferredSize().height + 6;
            if (table.getRowHeight(row) != h) table.setRowHeight(row, Math.min(h, 500));
            return this;
        }
    }
    private void copyToClipboard(String s) {
        try {
            java.awt.datatransfer.StringSelection ss = new java.awt.datatransfer.StringSelection(s);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(ss, null);
        } catch (Exception e) { stderr.println("[Decoder] Clipboard error: " + e); }
    }
    private void saveRowsToFile(java.util.List<String[]> rows) {
        JFileChooser fc = new JFileChooser(new File(SAVE_DIR));
        if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        File f = fc.getSelectedFile();
        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8))) {
            for (String[] r : rows) {
                pw.println("[" + r[0] + "]");
                pw.println(r[1]);
                pw.println();
            }
        } catch (Exception e) { stderr.println("[Decoder] Save error: " + e); }
    }
    private void showVariantsTable(String title, java.util.List<String[]> rows) {
        KVTableModel model = new KVTableModel(rows);
        JTable table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setRowSelectionAllowed(true);
        table.setColumnSelectionAllowed(false);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        table.getColumnModel().getColumn(0).setPreferredWidth(200);
        table.getColumnModel().getColumn(0).setCellRenderer(new TextAreaRenderer());
        table.getColumnModel().getColumn(1).setCellRenderer(new TextAreaRenderer());

        JScrollPane sp = new JScrollPane(table);
        sp.setPreferredSize(new Dimension(1000, 420));

        JButton btnCopySel = new JButton("Copy Selected");
        btnCopySel.addActionListener(ev -> {
            int[] sel = table.getSelectedRows();
            if (sel == null || sel.length == 0) return;
            StringBuilder sb = new StringBuilder();
            for (int r : sel) {
                String k = model.getValueAt(r,0).toString();
                String v = model.getValueAt(r,1).toString();
                sb.append("[").append(k).append("]\n").append(v).append("\n\n");
            }
            copyToClipboard(sb.toString());
        });

        JButton btnCopyAll = new JButton("Copy All");
        btnCopyAll.addActionListener(ev -> copyToClipboard(model.getAllAsText()));

        JButton btnSave = new JButton("Save All…");
        btnSave.addActionListener(ev -> saveRowsToFile(rows));

        JPanel south = new JPanel(new FlowLayout(FlowLayout.LEFT));
        south.add(btnCopySel); south.add(btnCopyAll); south.add(btnSave);

        JPanel wrap = new JPanel(new BorderLayout(8,8));
        wrap.add(sp, BorderLayout.CENTER);
        wrap.add(south, BorderLayout.SOUTH);

        JOptionPane.showMessageDialog(panel, wrap, title, JOptionPane.PLAIN_MESSAGE);
    }

    // Test Decode
    private void testManualDecode() {
        JPanel p = new JPanel(new BorderLayout(8,8));
        JTextArea input = new JTextArea(6, 80);
        p.add(new JScrollPane(input), BorderLayout.CENTER);

        JPanel opts = new JPanel(new GridLayout(2,5));
        JCheckBox oEU = new JCheckBox("LZ EU", true);
        JCheckBox oB64= new JCheckBox("LZ B64", true);
        JCheckBox oU16= new JCheckBox("LZ UTF16", true);
        JCheckBox oB64raw = new JCheckBox("Base64->human/comp", true);
        JCheckBox oHex = new JCheckBox("Hex->text", true);
        JCheckBox oB32 = new JCheckBox("Base32->text", true);
        JCheckBox oQP  = new JCheckBox("Quoted-Printable", true);
        opts.add(oEU); opts.add(oB64); opts.add(oU16); opts.add(oB64raw); opts.add(oHex);
        opts.add(oB32); opts.add(oQP);
        p.add(opts, BorderLayout.SOUTH);

        int rc = JOptionPane.showConfirmDialog(panel, p, "Test Decode", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (rc != JOptionPane.OK_OPTION) return;

        String in = input.getText().trim();
        if (in.isEmpty()) return;

        java.util.List<String[]> rows = new ArrayList<>();

        if (oEU.isSelected()) { String out = tryEU(in); if (accept(out)) rows.add(new String[]{"LZString EU", out}); }
        if (oB64.isSelected()) { String out = tryB64(in); if (accept(out)) rows.add(new String[]{"LZString Base64", out}); }
        if (oU16.isSelected()) { String out = tryUTF16(in); if (accept(out)) rows.add(new String[]{"LZString UTF16", out}); }

        if (oB64raw.isSelected()) {
            byte[] b = tryBase64(in);
            if (b != null) {
                String txt = bytesToUtf8IfHuman(b); if (accept(txt)) rows.add(new String[]{"Base64 -> text", txt});
                String gz = tryGzip(b);                   if (accept(gz)) rows.add(new String[]{"Base64 -> gzip", gz});
                String zl = tryZlib(b,false);             if (accept(zl)) rows.add(new String[]{"Base64 -> zlib", zl});
                String df = tryZlib(b,true);              if (accept(df)) rows.add(new String[]{"Base64 -> deflate", df});
                String br = tryViaReflectStream("org.brotli.dec.BrotliInputStream", b);
                if (accept(br)) rows.add(new String[]{"Base64 -> brotli", br});
                String lz4= tryViaReflectStream("net.jpountz.lz4.LZ4FrameInputStream", b);
                if (accept(lz4)) rows.add(new String[]{"Base64 -> lz4", lz4});
                String zs = tryViaReflectStream("com.github.luben.zstd.ZstdInputStream", b);
                if (accept(zs)) rows.add(new String[]{"Base64 -> zstd", zs});
                String sn = tryViaReflectStream("org.xerial.snappy.SnappyInputStream", b);
                if (accept(sn)) rows.add(new String[]{"Base64 -> snappy", sn});
            }
        }
        if (oHex.isSelected()) {
            byte[] h = tryHex(in);
            if (h != null) {
                String txt = bytesToUtf8IfHuman(h);
                if (accept(txt)) rows.add(new String[]{"Hex -> text", txt});
            }
        }
        if (oB32.isSelected()) {
            byte[] bb = tryBase32(in);
            if (bb != null) {
                String txt = bytesToUtf8IfHuman(bb);
                if (accept(txt)) rows.add(new String[]{"Base32 -> text", txt});
            }
        }
        if (oQP.isSelected()) {
            String qp = tryQuotedPrintable(in);
            if (accept(qp)) rows.add(new String[]{"Quoted-Printable -> text", qp});
        }

        if (rows.isEmpty()) rows.add(new String[]{"No decode", "(no human-friendly result)"});
        showVariantsTable("Decode Result", rows);
    }

    // Make Token (variants)
    private void makeTokenDialog() {
        JTextArea input = new JTextArea(10, 80);
        input.setLineWrap(true); input.setWrapStyleWord(true);

        JPanel p = new JPanel(new BorderLayout(8,8));
        p.add(new JScrollPane(input), BorderLayout.CENTER);

        JPanel opts = new JPanel(new GridLayout(3,4));
        JCheckBox eB64 = new JCheckBox("Base64", true);
        JCheckBox eB64U= new JCheckBox("Base64 URL-safe", true);
        JCheckBox eHex = new JCheckBox("Hex", true);
        JCheckBox eB32 = new JCheckBox("Base32", true);
        JCheckBox eQP  = new JCheckBox("Quoted-Printable", false);
        JCheckBox eGZ  = new JCheckBox("gzip+Base64", true);
        JCheckBox eDF  = new JCheckBox("deflate+Base64", true);
        JCheckBox eBR  = new JCheckBox("brotli+Base64 (if avail)", false);
        JCheckBox eLZ4 = new JCheckBox("lz4+Base64 (if avail)", false);
        JCheckBox eZST = new JCheckBox("zstd+Base64 (if avail)", false);
        JCheckBox eSNP = new JCheckBox("snappy+Base64 (if avail)", false);
        JCheckBox eLZSB64 = new JCheckBox("LZString->Base64 (python)", false);
        opts.add(eB64); opts.add(eB64U); opts.add(eHex); opts.add(eB32);
        opts.add(eQP);  opts.add(eGZ);  opts.add(eDF);  opts.add(eBR);
        opts.add(eLZ4); opts.add(eZST); opts.add(eSNP); opts.add(eLZSB64);
        p.add(opts, BorderLayout.SOUTH);

        int rc = JOptionPane.showConfirmDialog(panel, p, "Make Token Variants", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (rc != JOptionPane.OK_OPTION) return;

        final String src = Optional.ofNullable(input.getText()).orElse("");
        byte[] plain = src.getBytes(StandardCharsets.UTF_8);

        java.util.List<String[]> rows = new ArrayList<>();
        if (eB64.isSelected()) rows.add(new String[]{"Base64", Base64.getEncoder().encodeToString(plain)});
        if (eB64U.isSelected()) rows.add(new String[]{"Base64URL", Base64.getUrlEncoder().withoutPadding().encodeToString(plain)});
        if (eHex.isSelected())  rows.add(new String[]{"Hex", hexEncode(plain)});
        if (eB32.isSelected())  rows.add(new String[]{"Base32", base32Encode(plain)});
        if (eQP.isSelected())   rows.add(new String[]{"Quoted-Printable", qpEncode(plain)});

        if (eGZ.isSelected())  { byte[] gz = gzipCompress(plain);    if (gz != null) rows.add(new String[]{"gzip+Base64", Base64.getEncoder().encodeToString(gz)}); }
        if (eDF.isSelected())  { byte[] df = deflateCompress(plain); if (df != null) rows.add(new String[]{"deflate+Base64", Base64.getEncoder().encodeToString(df)}); }
        if (eBR.isSelected())  { byte[] br = reflectCompress("org.brotli.enc.BrotliOutputStream", plain); if (br != null) rows.add(new String[]{"brotli+Base64", Base64.getEncoder().encodeToString(br)}); }
        if (eLZ4.isSelected()) { byte[] lz4= reflectCompress("net.jpountz.lz4.LZ4FrameOutputStream", plain); if (lz4 != null) rows.add(new String[]{"lz4+Base64", Base64.getEncoder().encodeToString(lz4)}); }
        if (eZST.isSelected()) { byte[] zs = reflectCompress("com.github.luben.zstd.ZstdOutputStream", plain); if (zs != null) rows.add(new String[]{"zstd+Base64", Base64.getEncoder().encodeToString(zs)}); }
        if (eSNP.isSelected()) { byte[] sn = reflectCompress("org.xerial.snappy.SnappyOutputStream", plain); if (sn != null) rows.add(new String[]{"snappy+Base64", Base64.getEncoder().encodeToString(sn)}); }

        if (eLZSB64.isSelected()) {
            String lzs = compressToBase64ViaPython(src);
            if (lzs != null && !lzs.isEmpty()) rows.add(new String[]{"LZString->Base64", lzs});
            else rows.add(new String[]{"LZString->Base64", "(python lzstring not available)"});
        }

        if (rows.isEmpty()) rows.add(new String[]{"Info", "(no variants generated)"});
        showVariantsTable("Make Token Variants", rows);
    }

    // ================= Byte/codec helpers =================
    private byte[] tryBase64(String in) {
        if (in == null) return null;
        String t = in.trim();
        if (!t.matches("^[A-Za-z0-9_\\-+/=]+$")) return null;

        String norm = normalizeBase64(t);
        try {
            byte[] decoded = Base64.getDecoder().decode(norm);

            // Round-trip: re-encode and compare ignoring padding
            String re = Base64.getEncoder().encodeToString(decoded);
            String np = norm.replace("=", "");
            String rp = re.replace("=", "");
            if (rp.equals(np)) return decoded;

            // url-safe no-padding comparison
            String urlSafeRe = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
            if (urlSafeRe.equals(np)) return decoded;

            // For padded tokens allow if decoded text appears human
            if (t.contains("=")) {
                String s = new String(decoded, StandardCharsets.UTF_8);
                if (passesQuality(s)) return decoded;
            }
            return null;
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
    private byte[] tryHexBytes(String t) {
        try {
            String s = t.replaceAll("\\s+", "");
            if (s.length() % 2 != 0) return null;
            byte[] out = new byte[s.length() / 2];
            for (int i = 0; i < out.length; i++) {
                int hi = Character.digit(s.charAt(2*i), 16);
                int lo = Character.digit(s.charAt(2*i+1), 16);
                if (hi < 0 || lo < 0) return null;
                out[i] = (byte)((hi << 4) | lo);
            }
            return out;
        } catch (Exception e) { return null; }
    }
    private byte[] tryHex(String t) { return tryHexBytes(t); }
    private String hexEncode(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }
    private byte[] tryBase32(String s) {
        try { return base32Decode(s); } catch (Exception e) { return null; }
    }
    private String base32Encode(byte[] data) {
        final String ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0, bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int idx = (buffer >> (bitsLeft - 5)) & 0x1F;
                bitsLeft -= 5;
                out.append(ALPH.charAt(idx));
            }
        }
        if (bitsLeft > 0) out.append(ALPH.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        return out.toString();
    }
    private byte[] base32Decode(String s) {
        String t = s.trim().replace("=", "").toUpperCase(Locale.ROOT);
        final String ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0, bitsLeft = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream((t.length() * 5) / 8);
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            int val = ALPH.indexOf(c);
            if (val < 0) return null;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                baos.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return baos.toByteArray();
    }
    private String tryQuotedPrintable(String s) {
        try { return qpDecode(s); } catch (Exception e) { return null; }
    }
    private String qpEncode(byte[] in) {
        StringBuilder sb = new StringBuilder();
        for (byte b : in) {
            int c = b & 0xFF;
            if ((c >= 33 && c <= 126) && c != '=' && c != '?') sb.append((char)c);
            else sb.append('=').append(String.format("%02X", c));
        }
        return sb.toString();
    }
    private String qpDecode(String in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(in.length());
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            if (c == '=' && i + 2 < in.length()) {
                int hi = Character.digit(in.charAt(i+1), 16);
                int lo = Character.digit(in.charAt(i+2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) | lo);
                    i += 2;
                    continue;
                }
            }
            out.write((byte)c);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
    private String bytesToUtf8IfHuman(byte[] b) {
        if (b == null) return null;
        String s = new String(b, StandardCharsets.UTF_8);
        return passesQuality(s) ? s : null;
    }
    private String tryGzip(byte[] b) {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(b);
            GZIPInputStream gis = new GZIPInputStream(bais);
            return readAll(gis, MAX_DECODE_LEN);
        } catch (Exception e) { return null; }
    }
    private String tryZlib(byte[] b, boolean nowrap) {
        try {
            Inflater inflater = new Inflater(nowrap);
            inflater.setInput(b);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inflater.finished() && !inflater.needsInput()) {
                int r = inflater.inflate(buf);
                if (r <= 0) break;
                baos.write(buf, 0, r);
                if (baos.size() > MAX_DECODE_LEN) break;
            }
            inflater.end();
            String s = new String(baos.toByteArray(), StandardCharsets.UTF_8);
            return s.isEmpty() ? null : s;
        } catch (Exception e) { return null; }
    }
    private byte[] gzipCompress(byte[] plain) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gos = new GZIPOutputStream(baos)) {
                gos.write(plain);
            }
            return baos.toByteArray();
        } catch (Exception e) { return null; }
    }
    private byte[] deflateCompress(byte[] plain) {
        try {
            Deflater def = new Deflater(Deflater.DEFAULT_COMPRESSION, false);
            def.setInput(plain); def.finish();
            byte[] buf = new byte[plain.length * 2 + 64];
            int n = def.deflate(buf);
            return Arrays.copyOf(buf, n);
        } catch (Exception e) { return null; }
    }
    private String readAll(InputStream is, int max) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r;
        while ((r = is.read(buf)) != -1) {
            baos.write(buf, 0, r);
            if (baos.size() > max) break;
        }
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }
    private String tryViaReflectStream(String className, byte[] compressed) {
        try {
            Class<?> cls = Class.forName(className);
            ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
            java.lang.reflect.Constructor<?> ctor = cls.getConstructor(InputStream.class);
            InputStream is = (InputStream) ctor.newInstance(bais);
            return readAll(is, MAX_DECODE_LEN);
        } catch (Throwable t) { return null; }
    }
    private byte[] reflectCompress(String className, byte[] plain) {
        try {
            Class<?> cls = Class.forName(className);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            java.lang.reflect.Constructor<?> ctor = cls.getConstructor(OutputStream.class);
            OutputStream os = (OutputStream) ctor.newInstance(baos);
            os.write(plain);
            os.close();
            return baos.toByteArray();
        } catch (Throwable t) { return null; }
    }
    private boolean isAllowedContentType(String ct) {
        if (ct == null || ct.isEmpty()) return true;
        String t = ct.toLowerCase(Locale.ROOT);
        return t.contains("text/html") || t.contains("application/json") || t.contains("text/json")
                || t.contains("application/xml") || t.contains("text/xml") || t.contains("application/xhtml");
    }
    private String getHeaderValue(List<String> headers, String name) {
        for (String h : headers) {
            int idx = h.indexOf(':');
            if (idx < 0) continue;
            String n = h.substring(0, idx).trim();
            if (n.equalsIgnoreCase(name)) return h.substring(idx + 1).trim();
        }
        return null;
    }
    private String compressToBase64ViaPython(String src) {
        String[] candidates = new String[] {"python3", "python"};
        final String py = ""
                + "import sys\n"
                + "try:\n"
                + "  from lzstring import LZString\n"
                + "  data = sys.stdin.read()\n"
                + "  print(LZString().compressToBase64(data), end='')\n"
                + "except Exception as e:\n"
                + "  pass\n";
        for (String exe : candidates) {
            try {
                ProcessBuilder pb = new ProcessBuilder(exe, "-c", py);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                try (OutputStream os = p.getOutputStream()) {
                    os.write(src.getBytes(StandardCharsets.UTF_8));
                }
                String out;
                try (InputStream is = p.getInputStream()) {
                    out = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                }
                int code = p.waitFor();
                if (code == 0 && out != null && !out.isEmpty()) return out.trim();
            } catch (Exception ignore) {}
        }
        return null;
    }

}

// ==========================
// Pure-Java LZString port
// ==========================
class LZStringJava {
    private static final String BASE64_ALPHABET   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final String URI_SAFE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$";

    public static String decompressFromBase64(String input) {
        if (input == null) return null;
        final String s = input;
        return decompress(s.length(), 32, idx -> getBaseValue(BASE64_ALPHABET, s.charAt(idx)));
    }
    public static String decompressFromEncodedURIComponent(String input) {
        if (input == null) return null;
        final String s = input.replace(" ", "+");
        return decompress(s.length(), 32, idx -> getBaseValue(URI_SAFE_ALPHABET, s.charAt(idx)));
    }
    public static String decompressFromUTF16(String input) {
        if (input == null) return null;
        final String s = input;
        return decompress(s.length(), 16384, idx -> ((int) s.charAt(idx)) - 32);
    }

    private interface CharProvider { int at(int index); }
    private static String decompress(int length, int resetValue, CharProvider getBase) {
        List<String> dictionary = new ArrayList<>(4096);
        int enlargeIn = 4;
        int dictSize  = 4;
        int numBits   = 3;
        String entry;
        StringBuilder result = new StringBuilder();

        Data data = new Data(1, getBase.at(0), resetValue);
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
        return null;
    }

    private static int getBaseValue(String alphabet, char character) {
        int p = alphabet.indexOf(character);
        return (p >= 0) ? p : 0;
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
        int index, val, position, resetValue;
        Data(int index, int firstVal, int resetValue) {
            this.index = index; this.val = firstVal; this.position = resetValue; this.resetValue = resetValue;
        }
    }
}
