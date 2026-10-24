package tv.danmaku.bili;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.provider.Settings;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.FileReader;

final class ClockState {
    static String bootId(Context c) {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/sys/kernel/random/boot_id"))) { return r.readLine().trim(); }
        catch (Exception e) {
            int count = Settings.Global.getInt(c.getContentResolver(), "boot_count", -1);
            // Missing boot identity means no reusable synchronization, not a fabricated identity.
            return count >= 0 ? "boot-count-" + count : null;
        }
    }
    static void sync(Context c, JSONObject cfg) {
        try {
            long startWall = System.currentTimeMillis(), startMono = SystemClock.elapsedRealtime();
            JSONObject reply = Network.request(cfg.getString("endpoint") + "/v1/time", cfg.getString("token"), null);
            long endMono = SystemClock.elapsedRealtime(), endWall = System.currentTimeMillis();
            long roundTrip = endMono - startMono;
            if (Math.abs((endWall - startWall) - roundTrip) > 250) return;
            String boot = bootId(c); if (boot == null) return;
            long offset = reply.getLong("server_time_ms") - (startWall + roundTrip / 2);
            ProbeConfig.prefs(c).edit().putLong("clock_offset", offset).putLong("clock_uncertainty", roundTrip / 2 + 2)
                .putLong("clock_sync_wall", endWall).putLong("clock_sync_mono", endMono).putString("clock_boot", boot).commit();
        } catch (Exception ignored) { /* Emit null if no still-valid previous synchronization exists. */ }
    }
    static void add(Context c, JSONObject event, String boot, long wall, long mono) throws Exception {
        SharedPreferences p = ProbeConfig.prefs(c);
        long sm = p.getLong("clock_sync_mono", -1), age = mono - sm;
        boolean valid = boot != null && boot.equals(p.getString("clock_boot", "")) && sm >= 0 && age >= 0 && age <= 3600000
            && Math.abs((wall - p.getLong("clock_sync_wall", 0)) - age) <= 250;
        event.put("clock_offset_ms", valid ? p.getLong("clock_offset", 0) : JSONObject.NULL);
        event.put("clock_uncertainty_ms", valid ? p.getLong("clock_uncertainty", 0) + age / 10000 + 250 : JSONObject.NULL);
        event.put("clock_sync_age_ms", valid ? age : JSONObject.NULL);
    }
}
