package tv.danmaku.bili;

import android.accessibilityservice.AccessibilityService;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import org.json.*;
import java.util.List;

/** Self-liveness by default; fixed target-package UI steps only after an explicit start. */
public class ProbeAccessibilityService extends AccessibilityService {
    static volatile ProbeAccessibilityService active;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private int generation;
    private BuiltinUiRunner builtinRunner;
    private final Runnable heartbeat = new Runnable() {
        public void run() {
            String boot = ClockState.bootId(ProbeAccessibilityService.this);
            ProbeConfig.prefs(ProbeAccessibilityService.this).edit().putLong("service_heartbeat", System.currentTimeMillis())
                .putString("service_boot", boot == null ? "" : boot).apply();
            handler.postDelayed(this, 30000);
        }
    };
    @Override public void onServiceConnected() { active = this; handler.post(heartbeat); }
    @Override public void onAccessibilityEvent(AccessibilityEvent event) { /* Never collect event content. */ }
    @Override public void onInterrupt() { stopFlow(); }
    @Override public void onDestroy() { stopFlow(); handler.removeCallbacks(heartbeat); active = null; super.onDestroy(); }
    void stopFlow() { generation++; if (builtinRunner != null) { builtinRunner.cancel(); builtinRunner = null; } }
    boolean isBuiltinRunning() { return builtinRunner != null && builtinRunner.isRunning(); }
    void startBuiltinBatch(JSONObject context, JSONArray discovered, JSONObject fileResult) throws Exception {
        stopFlow(); builtinRunner = new BuiltinUiRunner(this, handler, context, discovered, fileResult); builtinRunner.start();
    }
    void startFlow(String json) throws Exception {
        JSONObject cfg = new JSONObject(json); String target = cfg.getString("package");
        if (!target.matches("[A-Za-z0-9_.]+")) throw new IllegalArgumentException("Invalid target package");
        JSONArray steps = cfg.getJSONArray("steps"); if (steps.length() < 1 || steps.length() > 50) throw new IllegalArgumentException("Use 1–50 fixed steps");
        stopFlow(); int runGeneration = generation;
        JSONObject trace = new JSONObject().put("schema", "actscope.device.ui.v1").put("target_package", target)
            .put("run_id", cfg.optString("run_id", "")).put("instance_id", cfg.optString("instance_id", "")).put("build_id", cfg.optString("build_id", ""))
            .put("started_at", System.currentTimeMillis()).put("steps", new JSONArray()).put("completed", false)
            .put("residue_verified", false).put("provenance_evidence", "");
        execute(cfg, trace, 0, runGeneration);
    }
    private void execute(JSONObject cfg, JSONObject trace, int index, int runGeneration) {
        handler.post(() -> {
            if (generation != runGeneration) return;
            try {
                JSONArray steps = cfg.getJSONArray("steps");
                if (index >= steps.length()) { trace.put("completed", true).put("finished_at", System.currentTimeMillis()); persist(trace); return; }
                JSONObject step = steps.getJSONObject(index); String operation = step.getString("action"), target = cfg.getString("package");
                JSONObject row = new JSONObject().put("index", index).put("action", operation).put("at", System.currentTimeMillis());
                boolean ok;
                if ("launch".equals(operation)) {
                    Intent intent = getPackageManager().getLaunchIntentForPackage(target);
                    ok = intent != null; if (ok) { intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); startActivity(intent); }
                } else if ("wait".equals(operation)) ok = true;
                else if ("click_id".equals(operation) || "assert_visible_id".equals(operation)) {
                    String id = step.getString("view_id");
                    if (!id.startsWith(target + ":id/")) throw new IllegalArgumentException("View ID must belong to target package");
                    AccessibilityNodeInfo root = getRootInActiveWindow(); ok = false;
                    if (root != null) {
                        try {
                            if (target.contentEquals(root.getPackageName() == null ? "" : root.getPackageName())) {
                                List<AccessibilityNodeInfo> nodes = root.findAccessibilityNodeInfosByViewId(id);
                                for (AccessibilityNodeInfo node : nodes) {
                                    if (!ok && node.isVisibleToUser()) ok = "assert_visible_id".equals(operation) || node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                                    node.recycle();
                                }
                            } else row.put("reason", "foreground_package_mismatch");
                        } finally { root.recycle(); }
                    }
                    row.put("view_id", id);
                } else throw new IllegalArgumentException("Supported: launch, wait, click_id, assert_visible_id");
                row.put("succeeded", ok); trace.getJSONArray("steps").put(row); persist(trace);
                if (!ok) { trace.put("stopped_reason", "step_failed"); persist(trace); return; }
                long delay = Math.min(30000, Math.max(250, step.optLong("wait_ms", 1000)));
                handler.postDelayed(() -> execute(cfg, trace, index + 1, runGeneration), delay);
            } catch (Exception e) { try { trace.put("error", e.toString()); persist(trace); } catch (Exception ignored) {} }
        });
    }
    private void persist(JSONObject trace) { ProbeConfig.prefs(this).edit().putString("ui_trace", trace.toString()).apply(); }
}
