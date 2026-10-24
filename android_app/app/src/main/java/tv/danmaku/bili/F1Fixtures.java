package tv.danmaku.bili;

import android.content.Context;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/** Only passive replacement B is bundled; the tester supplies the original APK. */
final class F1Fixtures {
    interface Source { InputStream open(String name) throws IOException; }
    final JSONObject manifest;
    final byte[] replacement;
    private F1Fixtures(JSONObject manifest, byte[] replacement) { this.manifest = manifest; this.replacement = replacement; }
    static F1Fixtures load(Context context) throws Exception { return load(name -> context.getAssets().open("f1/" + name)); }
    static F1Fixtures load(Source source) throws Exception {
        JSONObject manifest = new JSONObject(new String(read(source, "manifest.json"), StandardCharsets.UTF_8));
        if (!"org.actscope.f1fixture".equals(manifest.optString("package_name"))) throw new IOException("Unexpected fixture package");
        byte[] b = read(source, "actscope-f1-B.apk");
        JSONObject identity = manifest.getJSONObject("B");
        if (b.length != identity.getInt("size_bytes") || !FileProbe.digest(new ByteArrayInputStream(b)).equals(FileProbe.requireHash(identity.getString("sha256")))) throw new IOException("Fixture B identity mismatch");
        return new F1Fixtures(manifest, b);
    }
    private static byte[] read(Source source, String name) throws IOException {
        try (InputStream in = source.open(name); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] bytes = new byte[8192]; int n;
            while ((n = in.read(bytes)) != -1) { if (out.size() + n > 65536) throw new IOException("Fixture exceeds 64KiB"); out.write(bytes, 0, n); }
            if (out.size() == 0) throw new IOException("Empty fixture"); return out.toByteArray();
        }
    }
    JSONObject configuration(JSONObject options) throws Exception {
        JSONObject config = new JSONObject(options.toString());
        if (!config.has("roots")) config.put("roots", new JSONArray().put("/data/local/tmp").put("/sdcard").put("/data/app").put("/"));
        if (!config.has("window_seconds")) config.put("window_seconds", 300);
        if (!config.has("poll_ms")) config.put("poll_ms", 1000);
        if (!config.has("scan_timeout_ms")) config.put("scan_timeout_ms", 10000);
        if (!config.has("max_scan_entries")) config.put("max_scan_entries", 50000);
        // Ignore A-specific options left by older versions; any detected APK is eligible.
        config.remove("original_sha256"); config.remove("original_size_bytes"); config.remove("replacement_path");
        return config
            .put("replacement_sha256", manifest.getJSONObject("B").getString("sha256")).put("fixture_package", manifest.getString("package_name"))
            .put("replacement_mode", "manual");
    }
}
