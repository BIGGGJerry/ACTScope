package tv.danmaku.bili;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;

/** Persist message keys rather than translated sentences so system language changes apply to status too. */
final class UiStatus {
    static String encode(String message, Object... args) {
        try { return new JSONObject().put("message", message).put("args", new JSONArray(args)).toString(); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid status message", e); }
    }
    static String render(Context c, String encoded, int fallback) {
        try {
            JSONObject message = new JSONObject(encoded);
            int id = messageId(message.getString("message"));
            if (id == 0) return c.getString(fallback);
            JSONArray array = message.getJSONArray("args"); Object[] args = new Object[array.length()];
            for (int n = 0; n < args.length; n++) args[n] = array.get(n);
            if ("f6_scanning".equals(message.getString("message")) && args.length == 1)
                args[0] = c.getString("shizuku".equals(args[0]) ? R.string.channel_shizuku : R.string.channel_app);
            if ("status_sampled".equals(message.getString("message")) && args.length == 2) args[1] = value(c, args[1]);
            return c.getString(id, args);
        } catch (Exception e) { return c.getString(fallback); }
    }
    private static int messageId(String key) {
        switch (key) {
            case "f6_wait_shizuku": return R.string.f6_wait_shizuku;
            case "f6_scanning": return R.string.f6_scanning;
            case "f6_discovering": return R.string.f6_discovering;
            case "f6_no_targets": return R.string.f6_no_targets;
            case "f6_files_only": return R.string.f6_files_only;
            case "f6_needs_a11y": return R.string.f6_needs_a11y;
            case "f6_failure": return R.string.f6_failure;
            case "f6_ui_progress": return R.string.f6_ui_progress;
            case "status_sampled": return R.string.status_sampled;
            case "status_sample_error": return R.string.status_sample_error;
            case "status_upload_pending": return R.string.status_upload_pending;
            default: return 0;
        }
    }
    static void f6(Context c, String message, Object... args) {
        ProbeConfig.prefs(c).edit().putString("f6_message", encode(message, args)).apply();
    }
    static void telemetry(Context c, String message, Object... args) {
        ProbeConfig.prefs(c).edit().putString("telemetry_message", encode(message, args)).apply();
    }
    static String value(Context c, Object value) {
        return c.getString(Boolean.TRUE.equals(value) ? R.string.value_enabled : Boolean.FALSE.equals(value) ? R.string.value_disabled : R.string.value_unknown);
    }
    static String f6(Context c) {
        String encoded = ProbeConfig.prefs(c).getString("f6_message", "{}");
        String text = render(c, encoded, R.string.f6_idle);
        try {
            String key = new JSONObject(encoded).optString("message");
            JSONObject result = new JSONObject(ProbeConfig.prefs(c).getString("f6_result", "{}"));
            if (!"f6_ui_progress".equals(key) && !"f6_no_targets".equals(key) && !"f6_needs_a11y".equals(key) && !"f6_files_only".equals(key)) return text;
            if (result.has("error")) text += "\n" + c.getString(R.string.f6_scan_failed, result.optString("error"));
            if ("f6_no_targets".equals(key)) return text + packageSummary(c, result.optJSONArray("package_checks"));
            if (!"f6_ui_progress".equals(key)) return text;
            JSONObject trace = new JSONObject(ProbeConfig.prefs(c).getString("ui_trace", "{}"));
            if (trace.has("finished_at_device")) return text + "\n" + c.getString(trace.optBoolean("batch_execution_complete") ? R.string.f6_ui_done : R.string.f6_ui_interrupted) + packageSummary(c, trace.optJSONArray("apps"));
            JSONArray apps = trace.optJSONArray("apps");
            if (apps != null) for (int n = 0; n < apps.length(); n++) {
                JSONObject app = apps.getJSONObject(n);
                if ("running".equals(app.optString("status"))) return text + "\n" + c.getString(R.string.f6_ui_target, app.optString("target"), c.getString(R.string.ui_state_running));
            }
        } catch (Exception ignored) { }
        return text;
    }
    private static String packageSummary(Context c, JSONArray apps) throws Exception {
        if (apps == null) return "";
        StringBuilder out = new StringBuilder();
        for (int n = 0; n < apps.length(); n++) {
            JSONObject app = apps.getJSONObject(n);
            out.append('\n').append(c.getString(R.string.f6_ui_target, app.optString("package"), state(c, app.optString("status"))));
        }
        return out.toString();
    }
    private static String state(Context c, String state) {
        int id;
        switch (state) {
            case "ready": id = R.string.ui_state_ready; break;
            case "running": id = R.string.ui_state_running; break;
            case "flow_completed": id = R.string.ui_state_flow_completed; break;
            case "needs_manual_action": id = R.string.ui_state_needs_manual_action; break;
            case "timeout": id = R.string.ui_state_timeout; break;
            case "action_limit": id = R.string.ui_state_action_limit; break;
            case "view_tree_limit": id = R.string.ui_state_view_tree_limit; break;
            case "state_not_matched": id = R.string.ui_state_state_not_matched; break;
            case "view_not_matched": id = R.string.ui_state_view_not_matched; break;
            case "foreground_mismatch": id = R.string.ui_state_foreground_mismatch; break;
            case "repeated_state": id = R.string.ui_state_repeated_state; break;
            case "touch_failed": id = R.string.ui_state_touch_failed; break;
            case "execution_error": id = R.string.ui_state_execution_error; break;
            case "evidence_limit": id = R.string.ui_state_evidence_limit; break;
            case "stopped_by_user_or_service": id = R.string.ui_state_stopped_by_user_or_service; break;
            case "skipped_no_launcher": id = R.string.ui_state_skipped_no_launcher; break;
            case "skipped_not_installed": id = R.string.ui_state_skipped_not_installed; break;
            case "skipped_identity_guard": id = R.string.ui_state_skipped_identity_guard; break;
            case "skipped_disabled": id = R.string.ui_state_skipped_disabled; break;
            case "query_failed": id = R.string.ui_state_query_failed; break;
            default: id = R.string.ui_state_unknown;
        }
        return c.getString(id);
    }
}
