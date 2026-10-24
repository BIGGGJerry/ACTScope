package tv.danmaku.bili;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

final class BuiltinRules {
    static JSONObject load(Context c, String asset) throws Exception {
        try (InputStream in = c.getAssets().open(asset); ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
            byte[] b = new byte[8192]; int n; while ((n = in.read(b)) >= 0) bytes.write(b, 0, n);
            return new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
        }
    }
    static JSONArray discover(Context c) throws Exception {
        JSONArray result = new JSONArray(); JSONArray targets = load(c, "f6/catalog.json").getJSONArray("targets");
        for (int i = 0; i < targets.length(); i++) {
            JSONObject target = targets.getJSONObject(i); JSONArray candidates = target.getJSONArray("packages");
            for (int j = 0; j < candidates.length(); j++) {
                JSONObject candidate = candidates.getJSONObject(j); String pkg = candidate.getString("package");
                JSONObject row = new JSONObject().put("target", target.getString("name")).put("package", pkg)
                    .put("checked_at_device", System.currentTimeMillis()).put("query_scope", "explicit_manifest_query")
                    .put("installed", JSONObject.NULL).put("target_config", target);
                if (candidate.has("identity_note")) row.put("identity_note", candidate.getString("identity_note"));
                try {
                    PackageInfo info = c.getPackageManager().getPackageInfo(pkg, 0);
                    row.put("installed", true).put("version_name", info.versionName == null ? JSONObject.NULL : info.versionName)
                        .put("version_code", Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode)
                        .put("first_install_time", info.firstInstallTime).put("last_update_time", info.lastUpdateTime);
                    boolean enabled = info.applicationInfo != null && info.applicationInfo.enabled;
                    boolean brandAllowed = true; JSONArray guards = candidate.optJSONArray("manufacturer_guard");
                    if (guards != null) {
                        brandAllowed = false; String maker = (Build.MANUFACTURER + " " + Build.BRAND).toLowerCase(Locale.ROOT);
                        for (int k = 0; k < guards.length(); k++) if (maker.contains(guards.getString(k))) brandAllowed = true;
                    }
                    if (!brandAllowed) row.put("status", "skipped_identity_guard");
                    else if (!enabled) row.put("status", "skipped_disabled");
                    else if (c.getPackageManager().getLaunchIntentForPackage(pkg) == null) row.put("status", "skipped_no_launcher");
                    else row.put("status", "ready");
                } catch (PackageManager.NameNotFoundException e) { row.put("installed", false).put("status", "skipped_not_installed"); }
                catch (RuntimeException e) { row.put("status", "query_failed").put("error", e.toString()); }
                result.put(row);
            }
        }
        return result;
    }
}
