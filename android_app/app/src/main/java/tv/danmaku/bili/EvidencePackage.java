package tv.danmaku.bili;

import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Portable evidence layout; PNGs stay separate from the JSON, without base64 inflation. */
final class EvidencePackage {
    interface Sink { void write(String relative, String mime, InputStream input) throws Exception; }
    static JSONObject write(File filesDir, JSONObject bundle, String folder, Sink sink) throws Exception {
        JSONArray files = new JSONArray(), diagnostics = new JSONArray(), evidence = bundle.optJSONArray("ui_evidence");
        JSONObject report = new JSONObject().put("schema", "actscope.download_export.v1")
            .put("directory", "Download/ACTScope/" + folder).put("bundle_file", "actscope-device-evidence.json")
            .put("files", files).put("diagnostics", diagnostics);
        int images = 0, unavailable = 0; long imageBytes = 0;
        Set<String> used = new HashSet<>();
        if (evidence != null) for (int i = 0; i < evidence.length(); i++) {
            JSONObject item = evidence.getJSONObject(i), state = item.getJSONObject("content");
            String pkg = EvidenceFiles.component(state.optString("target_package", "unknown"));
            String stem = String.format(Locale.ROOT, "%04d_%s", i + 1, EvidenceFiles.component(state.optString("reason", "state")));
            String base = "apps/" + pkg + "/" + stem;
            JSONObject screenshot = state.optJSONObject("screenshot");
            if (screenshot == null) {
                screenshot = ScreenshotCapture.failure("legacy_result_has_no_screenshot"); state.put("screenshot", screenshot);
            }
            if ("saved".equals(screenshot.optString("status"))) {
                String ref = screenshot.optString("evidence_ref", "");
                File image = null; String hash = null;
                try {
                    image = EvidenceFiles.resolve(filesDir, ref);
                    if (!image.isFile() || !ref.endsWith(".png")) throw new IOException("Missing PNG evidence");
                    if (image.length() > EvidenceFiles.MAX_IMAGE_BYTES || images >= EvidenceFiles.MAX_IMAGES || imageBytes + image.length() > EvidenceFiles.MAX_IMAGE_TOTAL) throw new IOException("Screenshot export limit");
                    if (image.length() != screenshot.optLong("size_bytes", -1)) throw new IOException("Screenshot size mismatch");
                    hash = EvidenceFiles.sha256(image);
                    if (!hash.equals(screenshot.optString("sha256"))) throw new IOException("Screenshot hash mismatch");
                    try (InputStream in = new FileInputStream(image)) {
                        byte[] magic = new byte[8];
                        if (in.read(magic) != 8 || !Arrays.equals(magic, new byte[]{(byte)137, 80, 78, 71, 13, 10, 26, 10})) throw new IOException("Invalid PNG signature");
                    }
                } catch (Exception e) {
                    image = null;
                    unavailable++; screenshot.put("export_status", "unavailable");
                    diagnostics.put(new JSONObject().put("evidence_ref", item.optString("evidence_ref")).put("screenshot_ref", ref).put("reason", e.toString()));
                }
                if (image != null) {
                    String relative = base + ".png";
                    if (!used.add(relative)) throw new IOException("Duplicate export path");
                    try (InputStream in = new FileInputStream(image)) { sink.write(relative, "image/png", in); }
                    screenshot.put("export_relative_path", relative);
                    files.put(new JSONObject().put("path", relative).put("mime", "image/png").put("size_bytes", image.length()).put("sha256", hash));
                    images++; imageBytes += image.length();
                }
            } else {
                unavailable++;
                diagnostics.put(new JSONObject().put("evidence_ref", item.optString("evidence_ref")).put("reason", screenshot.optString("reason", screenshot.optString("status", "unknown"))));
            }
            byte[] bytes = state.toString(2).getBytes(StandardCharsets.UTF_8);
            sink.write(base + ".json", "application/json", new ByteArrayInputStream(bytes));
            files.put(new JSONObject().put("path", base + ".json").put("mime", "application/json").put("size_bytes", bytes.length));
        }
        JSONObject uiExport = bundle.optJSONObject("ui_evidence_export");
        boolean nodeExportComplete = uiExport == null || !uiExport.optBoolean("truncated", false);
        report.put("screenshots_exported", images).put("screenshot_bytes", imageBytes).put("screenshots_unavailable", unavailable)
            .put("evidence_export_complete", nodeExportComplete && unavailable == 0);
        bundle.put("download_export", report);
        sink.write("actscope-device-evidence.json", "application/json", new ByteArrayInputStream(bundle.toString(2).getBytes(StandardCharsets.UTF_8)));
        return report;
    }
}
