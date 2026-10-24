package tv.danmaku.bili;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONObject;
import java.net.URI;
import java.util.UUID;

final class ProbeConfig {
    static SharedPreferences prefs(Context c) { return c.getSharedPreferences("actscope", Context.MODE_PRIVATE); }
    static synchronized String instance(Context c) {
        SharedPreferences p = prefs(c);
        String id = p.getString("instance_id", null);
        if (id == null) { id = UUID.randomUUID().toString(); p.edit().putString("instance_id", id).commit(); }
        return id;
    }
    static JSONObject read(Context c) throws Exception { return new JSONObject(prefs(c).getString("config", "{}")); }
    static void save(Context c, String endpoint, String run, String token) throws Exception {
        URI u = new URI(endpoint);
        if (!"https".equalsIgnoreCase(u.getScheme()) || u.getHost() == null || u.getUserInfo() != null || u.getQuery() != null || u.getFragment() != null)
            throw new IllegalArgumentException(c.getString(R.string.backend_invalid));
        if (!ExperimentIds.valid(run) || token.trim().isEmpty() || token.contains("\n") || token.contains("\r"))
            throw new IllegalArgumentException(c.getString(R.string.run_token_invalid));
        JSONObject v = new JSONObject().put("endpoint", endpoint.replaceAll("/+$", "")).put("run_id", run).put("token", token);
        String oldEndpoint = read(c).optString("endpoint", "");
        SharedPreferences.Editor edit = prefs(c).edit().putString("config", v.toString()).putString("experiment_run_id", run);
        if (!oldEndpoint.equals(v.getString("endpoint"))) edit.remove("clock_boot");
        edit.commit();
    }
    static void status(Context c, String value) { prefs(c).edit().putString("status", value).apply(); }
}
