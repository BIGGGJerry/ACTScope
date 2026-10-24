package tv.danmaku.bili;

import android.accessibilityservice.GestureDescription;
import android.content.Context;
import android.content.Intent;
import android.graphics.Path;
import android.graphics.Rect;
import android.os.Handler;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityNodeInfo;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded, explicitly started execution of the shipped scripts on installed target packages. */
final class BuiltinUiRunner {
    private final ProbeAccessibilityService service;
    private final Handler handler;
    private final ScreenshotCapture screenshots;
    private final JSONObject context, fileResult, trace;
    private final JSONArray apps;
    private final String batchId = UUID.randomUUID().toString();
    private final Map<String, Integer> visits = new HashMap<>();
    private static final long MAX_EVIDENCE_BYTES = 4L * 1024 * 1024;
    private static final int MAX_SNAPSHOT_BYTES = 256 * 1024, MAX_SNAPSHOTS = 128;
    private long evidenceBytes;
    private int evidenceCount;
    private long screenshotBytes;
    private int screenshotCount, screenshotFailures;
    private boolean screenshotPending;
    private String afterTouch;
    private int appIndex = -1, sequence, actionCount;
    private static final class EvidenceLimitException extends IOException { EvidenceLimitException(String message) { super(message); } }
    private JSONObject current, target, operation;
    private LegacyUiScript script;
    private int eventIndex;
    private long appDeadline, waitStarted;
    private boolean cancelled, finished;
    private final Runnable tick = this::step;
    private int actionGeneration;
    private final Runnable watchdog = () -> { if (!cancelled && !finished && current != null && "running".equals(current.optString("status"))) fail("timeout", "Per-app deadline exceeded, including pending gesture callbacks"); };

    BuiltinUiRunner(ProbeAccessibilityService service, Handler handler, JSONObject context, JSONArray discovered, JSONObject fileResult) throws Exception {
        this.service = service; this.handler = handler; this.context = context; this.fileResult = fileResult;
        screenshots = new ScreenshotCapture(service, handler);
        apps = new JSONArray(discovered.toString());
        trace = new JSONObject().put("schema", "actscope.device.ui_batch.v1").put("run_id", context.getString("run_id"))
            .put("instance_id", context.getString("instance_id")).put("build_id", context.getString("build_id"))
            .put("batch_id", batchId).put("started_at_device", System.currentTimeMillis()).put("apps", apps)
            .put("batch_execution_complete", false).put("ui_semantic_review_complete", false);
    }
    void start() { nextApp(); }
    boolean isRunning() { return !finished && !cancelled; }
    void cancel() {
        if (finished) return;
        cancelled = true; actionGeneration++; handler.removeCallbacks(tick); handler.removeCallbacks(watchdog);
        try {
            if (current != null && "running".equals(current.optString("status"))) current.put("status", "stopped_by_user_or_service");
            trace.put("stopped_reason", "user_or_service_interrupt"); complete(false);
        } catch (Exception ignored) {}
    }
    private void nextApp() {
        if (cancelled) return;
        try {
            current = null; operation = null; afterTouch = null; screenshotPending = false; visits.clear(); actionCount = 0; actionGeneration++; handler.removeCallbacks(watchdog);
            while (++appIndex < apps.length()) {
                JSONObject row = apps.getJSONObject(appIndex);
                if (!"ready".equals(row.optString("status"))) continue;
                current = row; target = row.getJSONObject("target_config");
                JSONObject doc = BuiltinRules.load(service, target.getString("script_asset"));
                script = new LegacyUiScript(doc, target);
                current.put("status", "running").put("events", new JSONArray()).put("evidence_refs", new JSONArray())
                    .put("script_source", target.getString("source")).put("script_sha256", target.getString("source_sha256"))
                    .put("started_at_device", System.currentTimeMillis()).put("ui_residue_status", "unknown_requires_review");
                Intent launch = service.getPackageManager().getLaunchIntentForPackage(current.getString("package"));
                if (launch == null) { current.put("status", "skipped_no_launcher"); continue; }
                appDeadline = SystemClock.elapsedRealtime() + target.optLong("app_timeout_ms", 120000);
                waitStarted = SystemClock.elapsedRealtime();
                handler.postDelayed(watchdog, target.optLong("app_timeout_ms", 120000));
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); service.startActivity(launch);
                addEvent(new JSONObject().put("action", "launch_existing_app").put("succeeded", true));
                persist(); schedule(Math.max(1500, target.optLong("interval_ms", 1200))); return;
            }
            complete(true);
        } catch (Exception e) { fail("execution_error", e.toString()); }
    }
    private void schedule(long ms) { handler.removeCallbacks(tick); if (!cancelled && !finished) handler.postDelayed(tick, ms); }
    private void step() {
        if (cancelled || finished || current == null || screenshotPending) return;
        try {
            if (SystemClock.elapsedRealtime() > appDeadline) { fail("timeout", "Per-app deadline exceeded"); return; }
            if (afterTouch == null && actionCount >= target.optInt("max_actions", 40)) { fail("action_limit", "Bounded script action limit"); return; }
            try (Capture capture = new Capture(service, current.getString("package"))) {
                if (!capture.targetVisible) {
                    if (SystemClock.elapsedRealtime() - waitStarted < 6000 && actionCount == 0) { schedule(500); return; }
                    addEvent(new JSONObject().put("action", "scope_guard").put("foreground_package", capture.foreground).put("succeeded", false));
                    fail("foreground_mismatch", "Target package is not the active window; no action sent"); return;
                }
                if (afterTouch != null) {
                    String ref = saveCapture(capture, "after_touch");
                    addEvent(new JSONObject().put("action", "after_touch_visible_state").put("target_view", afterTouch).put("evidence_ref", ref));
                    afterTouch = null; checkpoint(ref, () -> schedule(0)); return;
                }
                if (capture.truncated) { captureAndFail(capture, "coverage_limit", "view_tree_limit", "Visible-state capture exceeded 600 nodes"); return; }
                String manual = script.manualBlock(capture.metadata);
                if (manual != null) { captureAndFail(capture, "manual_required", "needs_manual_action", manual); return; }
                if (operation == null) {
                    JSONObject decision = script.next(capture.metadata);
                    if (decision == null) {
                        if (SystemClock.elapsedRealtime() - waitStarted < target.optLong("step_timeout_ms", 12000)) { schedule(700); return; }
                        captureAndFail(capture, "unmatched_state", "state_not_matched", "Script version/language/state did not match; no exploratory actions"); return;
                    }
                    if (decision.has("manual_reason")) { captureAndFail(capture, "manual_required", "needs_manual_action", decision.getString("manual_reason")); return; }
                    String state = decision.getString("state"); int seen = visits.containsKey(state) ? visits.get(state) + 1 : 1; visits.put(state, seen);
                    if (seen > 3) { captureAndFail(capture, "repeated_state", "repeated_state", "Same state matched more than three times"); return; }
                    operation = decision; eventIndex = 0;
                    String ref = saveCapture(capture, "matched_state");
                    addEvent(new JSONObject().put("action", "match_state").put("state", state).put("operation", decision.getString("operation")).put("succeeded", true).put("evidence_ref", ref));
                    checkpoint(ref, () -> schedule(300)); return;
                }
                JSONArray events = operation.getJSONArray("events");
                if (eventIndex >= events.length()) { operation = null; waitStarted = SystemClock.elapsedRealtime(); schedule(300); return; }
                JSONObject event = events.getJSONObject(eventIndex); String type = event.getString("event_type");
                if ("exit".equals(type)) {
                    String ref = saveCapture(capture, "script_exit_visible_state");
                    addEvent(new JSONObject().put("action", "exit_script").put("succeeded", true).put("evidence_ref", ref));
                    checkpoint(ref, () -> finishApp("flow_completed", "Original script exit reached; visible content still needs provenance review")); return;
                }
                String view = event.getString("target_view"); int found = script.find(view, capture.metadata);
                if (found < 0) {
                    if (SystemClock.elapsedRealtime() - waitStarted < target.optLong("step_timeout_ms", 12000)) { schedule(500); return; }
                    captureAndFail(capture, "target_view_missing", "view_not_matched", "Missing view " + view); return;
                }
                JSONObject nodeInfo = capture.metadata.getJSONObject(found);
                if (LegacyUiScript.unsafeActionText(nodeInfo)) { captureAndFail(capture, "unsafe_action_guard", "needs_manual_action", "Login/consent/destructive action text on " + view); return; }
                String ref = saveCapture(capture, "before_touch");
                JSONObject record = new JSONObject().put("action", "touch").put("target_view", view).put("state", operation.getString("state"))
                    .put("operation", operation.getString("operation")).put("evidence_ref", ref);
                checkpoint(ref, () -> performTouch(record, view));
            }
        } catch (EvidenceLimitException e) {
            try { current.put("status", "evidence_limit").put("reason", e.getMessage()); trace.put("evidence_truncated", true).put("stopped_reason", e.getMessage()); fileResult.put("evidence_truncated", true); complete(false); }
            catch (Exception ignored) { fail("evidence_limit", e.toString()); }
        } catch (Exception e) { fail("execution_error", e.toString()); }
    }
    private interface Continuation { void run() throws Exception; }
    private void captureAndFail(Capture capture, String reason, String status, String detail) throws Exception {
        checkpoint(saveCapture(capture, reason), () -> finishApp(status, detail));
    }
    private void checkpoint(String ref, Continuation next) throws Exception {
        screenshotPending = true;
        int checkpointGeneration = ++actionGeneration;
        String imageRef = ref.substring(0, ref.length() - 5) + ".png";
        File image = EvidenceFiles.resolve(service.getFilesDir(), imageRef);
        java.util.function.Consumer<JSONObject> accept = result -> {
            if (cancelled || finished || checkpointGeneration != actionGeneration) { image.delete(); return; }
            try {
                if ("saved".equals(result.optString("status"))) {
                    if (screenshotBytes + image.length() > EvidenceFiles.MAX_IMAGE_TOTAL) { image.delete(); result = ScreenshotCapture.failure("batch_screenshot_limit_128MiB"); }
                    else { screenshotCount++; screenshotBytes += image.length(); result.put("evidence_ref", imageRef); }
                }
                if (!"saved".equals(result.optString("status"))) screenshotFailures++;
                File state = EvidenceFiles.resolve(service.getFilesDir(), ref);
                JSONObject data = new JSONObject(new String(java.nio.file.Files.readAllBytes(state.toPath()), StandardCharsets.UTF_8));
                data.put("screenshot", result);
                byte[] updated = data.toString().getBytes(StandardCharsets.UTF_8);
                evidenceBytes += updated.length - state.length();
                try (OutputStream out = new FileOutputStream(state)) { out.write(updated); }
                trace.put("evidence_bytes", evidenceBytes);
                trace.put("screenshot_count", screenshotCount).put("screenshot_bytes", screenshotBytes).put("screenshot_unavailable_count", screenshotFailures);
                screenshotPending = false; persist(); next.run();
            } catch (Exception e) { screenshotPending = false; fail("execution_error", e.toString()); }
        };
        if (screenshotCount >= EvidenceFiles.MAX_IMAGES || screenshotBytes >= EvidenceFiles.MAX_IMAGE_TOTAL) accept.accept(ScreenshotCapture.failure("batch_screenshot_limit"));
        else screenshots.capture(current.getString("package"), image, accept);
    }
    /** Re-read the target view after the asynchronous screenshot; never reuse stale nodes. */
    private void performTouch(JSONObject record, String view) throws Exception {
        try (Capture capture = new Capture(service, current.getString("package"))) {
            if (!capture.targetVisible) { fail("foreground_mismatch", "Target left foreground during screenshot; no action sent"); return; }
            int found = script.find(view, capture.metadata);
            if (found < 0 || capture.truncated || LegacyUiScript.unsafeActionText(capture.metadata.getJSONObject(found))) {
                fail("view_not_matched", "Target view changed during screenshot; no action sent"); return;
            }
            AccessibilityNodeInfo node = capture.nodes.get(found); actionCount++;
            if (clickAccessible(node, current.getString("package"))) { actionComplete(record, true, "accessibility_click"); return; }
            Rect bounds = new Rect(); node.getBoundsInScreen(bounds);
            if (bounds.isEmpty() || !node.isVisibleToUser()) { actionComplete(record, false, "invalid_bounds"); return; }
            Path path = new Path(); path.moveTo(bounds.exactCenterX(), bounds.exactCenterY());
            GestureDescription gesture = new GestureDescription.Builder().addStroke(new GestureDescription.StrokeDescription(path, 0, 80)).build();
            final int gestureGeneration = ++actionGeneration;
            boolean sent = service.dispatchGesture(gesture, new android.accessibilityservice.AccessibilityService.GestureResultCallback() {
                @Override public void onCompleted(GestureDescription gesture) { if (gestureGeneration == actionGeneration) actionComplete(record, true, "bounded_gesture"); }
                @Override public void onCancelled(GestureDescription gesture) { if (gestureGeneration == actionGeneration) actionComplete(record, false, "gesture_cancelled"); }
            }, handler);
            if (!sent) actionComplete(record, false, "gesture_rejected");
        }
    }
    private boolean clickAccessible(AccessibilityNodeInfo node, String pkg) {
        if (node.isEnabled() && node.isClickable() && node.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return true;
        AccessibilityNodeInfo parent = node.getParent();
        try {
            for (int n = 0; n < 4 && parent != null; n++) {
                if (!pkg.contentEquals(parent.getPackageName() == null ? "" : parent.getPackageName())) return false;
                if (parent.isEnabled() && parent.isClickable() && parent.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return true;
                AccessibilityNodeInfo next = parent.getParent(); parent.recycle(); parent = next;
            }
            return false;
        } finally { if (parent != null) parent.recycle(); }
    }
    private void actionComplete(JSONObject record, boolean succeeded, String method) {
        if (cancelled || finished) return;
        try {
            record.put("succeeded", succeeded).put("method", method); addEvent(record);
            if (!succeeded) { fail("touch_failed", method); return; }
            afterTouch = record.getString("target_view");
            eventIndex++; waitStarted = SystemClock.elapsedRealtime(); persist(); schedule(target.optLong("interval_ms", 1200));
        } catch (Exception e) { fail("execution_error", e.toString()); }
    }
    private void addEvent(JSONObject event) throws Exception { event.put("at_device", System.currentTimeMillis()); current.getJSONArray("events").put(event); }
    private void fail(String status, String reason) {
        if (cancelled || finished) return;
        if (current == null) { try { trace.put("fatal_error", reason); complete(false); } catch (Exception ignored) {} return; }
        try {
            if (!screenshotPending) try (Capture capture = new Capture(service, current.getString("package"))) {
                if (capture.targetVisible) { captureAndFail(capture, "stopped_" + status, status, reason); return; }
            }
            finishApp(status, reason);
        } catch (Exception e) { try { finishApp(status, reason + "; final capture unavailable: " + e); } catch (Exception fatal) { try { trace.put("fatal_error", fatal.toString()); complete(false); } catch (Exception ignored) {} } }
    }
    private void finishApp(String status, String reason) throws Exception {
        actionGeneration++; screenshotPending = false; handler.removeCallbacks(watchdog); handler.removeCallbacks(tick);
        current.put("status", status).put("reason", reason).put("finished_at_device", System.currentTimeMillis());
        persist(); handler.postDelayed(this::nextApp, 700);
    }
    private void complete(boolean attemptedAll) throws Exception {
        finished = true; actionGeneration++; handler.removeCallbacks(tick); handler.removeCallbacks(watchdog); trace.put("batch_execution_complete", attemptedAll).put("finished_at_device", System.currentTimeMillis());
        fileResult.put("batch_execution_complete", attemptedAll).put("ui_execution_status", attemptedAll ? "finished_requires_review" : "interrupted");
        persist();
        screenshots.close();
        Intent intent = new Intent(service, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        service.startActivity(intent);
    }
    private void persist() throws Exception {
        int ready = 0, completed = 0, skipped = 0, failed = 0;
        for (int i = 0; i < apps.length(); i++) { String s = apps.getJSONObject(i).optString("status"); if (s.startsWith("skipped")) skipped++; else if ("flow_completed".equals(s)) completed++; else if ("ready".equals(s) || "running".equals(s)) ready++; else failed++; }
        fileResult.put("ui_scan_complete", false).put("ui", new JSONArray())
            .put("ui_execution_coverage", new JSONObject().put("flow_completed", completed).put("skipped", skipped).put("failed_or_manual", failed).put("remaining", ready))
            .put("package_checks", apps).put("ui_trace_schema", "actscope.device.ui_batch.v1");
        ProbeConfig.prefs(service).edit().putString("f6_result", fileResult.toString()).putString("ui_trace", trace.toString()).apply();
        UiStatus.f6(service, "f6_ui_progress", completed, skipped, failed, ready);
    }
    private String saveCapture(Capture capture, String reason) throws Exception {
        String relative = "f6-ui/" + context.getString("run_id") + "/" + batchId + "/" + current.getString("target") + "_" + (++sequence) + ".json";
        File file = new File(service.getFilesDir(), relative); File parent = file.getParentFile(); if (!parent.isDirectory() && !parent.mkdirs()) throw new IOException("Cannot create evidence directory");
        JSONArray visible = new JSONArray(); for (int i = 0; i < capture.metadata.length(); i++) { JSONObject node = capture.metadata.getJSONObject(i); if (node.optBoolean("visible", false)) visible.put(node); }
        JSONObject data = new JSONObject().put("schema", "actscope.device.visible_state.v1").put("run_id", context.getString("run_id"))
            .put("instance_id", context.getString("instance_id")).put("target_package", current.getString("package"))
            .put("observed_at_device", System.currentTimeMillis()).put("reason", reason).put("nodes", visible).put("truncated", capture.truncated)
            .put("screenshot", new JSONObject().put("status", "pending"));
        int removed = 0; byte[] bytes = data.toString().getBytes(StandardCharsets.UTF_8);
        // Reserve room for the asynchronously attached screenshot descriptor.
        while (bytes.length > MAX_SNAPSHOT_BYTES - 2048 && visible.length() > 0) {
            visible.remove(visible.length() - 1); removed++;
            data.put("truncated", true).put("nodes_omitted", removed); bytes = data.toString().getBytes(StandardCharsets.UTF_8);
        }
        if (evidenceCount >= MAX_SNAPSHOTS || evidenceBytes + bytes.length + 2048 > MAX_EVIDENCE_BYTES) {
            trace.put("evidence_omitted", trace.optInt("evidence_omitted", 0) + 1);
            throw new EvidenceLimitException("Per-batch evidence bound reached (4MiB / 128 snapshots)");
        }
        try (OutputStream out = new FileOutputStream(file)) { out.write(bytes); }
        evidenceCount++; evidenceBytes += bytes.length;
        trace.put("evidence_bytes", evidenceBytes).put("evidence_count", evidenceCount);
        current.getJSONArray("evidence_refs").put(relative);
        if (removed > 0) throw new EvidenceLimitException("Snapshot exceeded 256KiB; partial snapshot retained and execution stopped");
        return relative;
    }
    static JSONObject exportEvidence(Context c, JSONObject trace) throws Exception {
        JSONArray out = new JSONArray(), diagnostics = new JSONArray(), apps = trace.optJSONArray("apps");
        JSONObject report = new JSONObject().put("items", out).put("diagnostics", diagnostics).put("truncated", false);
        if (apps == null) return report.put("bytes", 0).put("omitted_count", 0).put("missing_count", 0);
        Set<String> seen = new HashSet<>(); long total = 0; int omitted = 0, missing = 0;
        File root = new File(c.getFilesDir(), "f6-ui").getCanonicalFile();
        for (int i = 0; i < apps.length(); i++) {
            JSONArray refs = apps.getJSONObject(i).optJSONArray("evidence_refs"); if (refs == null) continue;
            for (int j = 0; j < refs.length(); j++) {
                String ref = refs.getString(j); if (!seen.add(ref)) continue; File f = new File(c.getFilesDir(), ref).getCanonicalFile();
                String problem = null;
                if (!f.getPath().startsWith(root.getPath() + File.separator)) problem = "invalid_reference";
                else if (!f.isFile()) { problem = "missing"; missing++; }
                else if (f.length() > MAX_SNAPSHOT_BYTES || total + f.length() > MAX_EVIDENCE_BYTES || out.length() >= MAX_SNAPSHOTS) problem = "export_size_limit";
                if (problem != null) { omitted++; diagnostics.put(new JSONObject().put("evidence_ref", ref).put("reason", problem)); continue; }
                try (InputStream in = new FileInputStream(f); ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
                    byte[] b = new byte[8192]; int n;
                    while ((n = in.read(b)) >= 0) { bytes.write(b, 0, n); if (bytes.size() > MAX_SNAPSHOT_BYTES) throw new IOException("Snapshot grew beyond export limit"); }
                    out.put(new JSONObject().put("evidence_ref", ref).put("content", new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8)))); total += bytes.size();
                } catch (Exception e) { omitted++; diagnostics.put(new JSONObject().put("evidence_ref", ref).put("reason", "read_failed").put("detail", e.toString())); }
            }
        }
        return report.put("bytes", total).put("omitted_count", omitted).put("missing_count", missing).put("truncated", omitted > 0);
    }
    private static String small(CharSequence value) { if (value == null) return ""; String s = value.toString(); return s.length() > 160 ? s.substring(0, 160) : s; }
    private static final class Capture implements AutoCloseable {
        final List<AccessibilityNodeInfo> nodes = new ArrayList<>(); final JSONArray metadata = new JSONArray();
        final String foreground; final boolean targetVisible; boolean truncated;
        Capture(ProbeAccessibilityService service, String target) throws Exception {
            AccessibilityNodeInfo root = service.getRootInActiveWindow();
            foreground = root == null ? "" : small(root.getPackageName()); targetVisible = root != null && target.equals(foreground);
            if (!targetVisible) { if (root != null) root.recycle(); return; }
            ArrayDeque<AccessibilityNodeInfo> queue = new ArrayDeque<>(); queue.add(root);
            while (!queue.isEmpty() && nodes.size() < 600) {
                AccessibilityNodeInfo node = queue.remove(); nodes.add(node);
                boolean visible = node.isVisibleToUser() && target.contentEquals(node.getPackageName() == null ? "" : node.getPackageName());
                JSONObject row = new JSONObject().put("visible", visible);
                if (visible) {
                    Rect bounds = new Rect(); node.getBoundsInScreen(bounds);
                    row.put("text", node.isPassword() ? "[password redacted]" : small(node.getText()))
                        .put("content_desc", node.isPassword() ? "[password redacted]" : small(node.getContentDescription()))
                        .put("resource_id", small(node.getViewIdResourceName())).put("class", small(node.getClassName()))
                        .put("bounds", new JSONArray().put(bounds.left).put(bounds.top).put(bounds.right).put(bounds.bottom))
                        .put("clickable", node.isClickable()).put("enabled", node.isEnabled());
                }
                metadata.put(row);
                for (int i = 0; i < node.getChildCount(); i++) { AccessibilityNodeInfo child = node.getChild(i); if (child != null) queue.add(child); }
                if (queue.size() > 1200) { truncated = true; break; }
            }
            if (!queue.isEmpty()) truncated = true;
            while (!queue.isEmpty()) queue.remove().recycle();
        }
        public void close() { for (AccessibilityNodeInfo node : nodes) node.recycle(); }
    }
}
