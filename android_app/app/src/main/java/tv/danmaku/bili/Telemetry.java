package tv.danmaku.bili;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ServiceInfo;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityManager;
import androidx.work.*;
import org.json.JSONObject;
import java.util.List;
import java.util.concurrent.TimeUnit;

final class Telemetry {
    static final String PERIODIC = "actscope-sample", SEND = "actscope-send";
    static String component(Context c) { return new ComponentName(c, ProbeAccessibilityService.class).flattenToString(); }
    static Object enabled(Context c) {
        try {
            AccessibilityManager m = (AccessibilityManager) c.getSystemService(Context.ACCESSIBILITY_SERVICE);
            if (m == null) return JSONObject.NULL;
            List<AccessibilityServiceInfo> items = m.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
            if (items == null) return JSONObject.NULL;
            for (AccessibilityServiceInfo item : items) {
                if (item.getResolveInfo() == null || item.getResolveInfo().serviceInfo == null) continue;
                ServiceInfo s = item.getResolveInfo().serviceInfo;
                if (component(c).equals(new ComponentName(s.packageName, s.name).flattenToString())) return true;
            }
            return false;
        } catch (RuntimeException e) { return JSONObject.NULL; }
    }
    static synchronized long sample(Context c) throws Exception {
        JSONObject cfg = ProbeConfig.read(c); cfg.getString("run_id");
        ClockState.sync(c, cfg);
        long wall = System.currentTimeMillis(), mono = SystemClock.elapsedRealtime(); String boot = ClockState.bootId(c);
        Object enabled = enabled(c);
        Object deviceAdmin = ProbePermissions.deviceAdminEnabled(c);
        Object notificationListener = ProbePermissions.notificationListenerEnabled(c);
        long sampled = System.currentTimeMillis();
        JSONObject event = new JSONObject().put("run_id", cfg.getString("run_id")).put("instance_id", ProbeConfig.instance(c))
            .put("sampled_at_device", wall).put("build_id", BuildConfig.PROBE_BUILD_ID).put("a11y_component", component(c))
            .put("a11y_enabled", enabled).put("a11y_sampled_at", sampled)
            .put("device_admin_enabled", deviceAdmin).put("notification_listener_enabled", notificationListener)
            .put("boot_id", boot == null ? JSONObject.NULL : boot).put("elapsed_realtime_ms", mono);
        long hb = ProbeConfig.prefs(c).getLong("service_heartbeat", 0);
        boolean sameBoot = boot != null && boot.equals(ProbeConfig.prefs(c).getString("service_boot", ""));
        event.put("service_last_heartbeat", sameBoot && hb > 0 ? hb : JSONObject.NULL);
        ClockState.add(c, event, boot, wall, mono);
        try (TelemetryStore db = new TelemetryStore(c)) {
            long seq = db.enqueue(event, cfg);
            UiStatus.telemetry(c, "status_sampled", seq, enabled, deviceAdmin, notificationListener);
            return seq;
        }
    }
    static void start(Context c, int minutes) {
        if (minutes < 15) throw new IllegalArgumentException(c.getString(R.string.period_invalid));
        ProbeConfig.prefs(c).edit().putBoolean("sampling", true).putInt("period_minutes", minutes).commit();
        WorkManager.getInstance(c).enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.UPDATE,
            new PeriodicWorkRequest.Builder(SampleWorker.class, minutes, TimeUnit.MINUTES).build());
        immediate(c);
    }
    static void immediate(Context c) { WorkManager.getInstance(c).enqueue(new OneTimeWorkRequest.Builder(SampleWorker.class).addTag(PERIODIC).build()); }
    static void upload(Context c) {
        OneTimeWorkRequest job = new OneTimeWorkRequest.Builder(SendWorker.class)
            .setConstraints(new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS).build();
        WorkManager.getInstance(c).enqueueUniqueWork(SEND, ExistingWorkPolicy.APPEND_OR_REPLACE, job);
    }
    static void stop(Context c) {
        ProbeConfig.prefs(c).edit().putBoolean("sampling", false).commit();
        WorkManager.getInstance(c).cancelUniqueWork(PERIODIC); WorkManager.getInstance(c).cancelAllWorkByTag(PERIODIC);
        WorkManager.getInstance(c).cancelUniqueWork(SEND);
    }
}
