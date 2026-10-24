package tv.danmaku.bili;

import android.os.Process;
import org.json.*;
import java.io.File;

/** Shizuku observation and an explicit action on a tester-selected APK candidate. */
public class UserService extends IUserService.Stub {
    private F1Watch watch;
    @Override public synchronized void destroy() { if (watch != null) try { watch.stop(); } catch (Exception ignored) {} System.exit(0); }
    @Override public synchronized String startWatch(String json) {
        try {
            JSONObject cfg = new JSONObject(json);
            return start(cfg, FileProbe.controlledReplacement(new File(cfg.getString("replacement_path")), cfg.getString("replacement_sha256")));
        } catch (Exception e) { return error(e); }
    }
    @Override public synchronized String startManualWatch(String json, byte[] replacement) {
        try {
            if (replacement == null || replacement.length > 65536) throw new F1Watch.Refused("invalid_replacement");
            return start(new JSONObject(json), replacement);
        } catch (Exception e) { return error(e); }
    }
    private String start(JSONObject cfg, byte[] replacement) throws Exception {
        requireShell();
        if (watch != null && watch.isRunning()) throw new F1Watch.Refused("watch_already_running");
        watch = new F1Watch(cfg, replacement, "uid=" + Process.myUid()); watch.start(); return watch.status();
    }
    @Override public synchronized String attemptHijack(String watchId, String candidateId, boolean normalBaselineVerified) {
        try { requireShell(); if (watch == null) throw new F1Watch.Refused("watch_missing"); return watch.attempt(watchId, candidateId, normalBaselineVerified); }
        catch (Exception e) { return error(e); }
    }
    private void requireShell() throws F1Watch.Refused { if (Process.myUid() != 2000) throw new F1Watch.Refused("requires_shell_uid_2000"); }
    @Override public synchronized String status() { try { return watch == null ? "{}" : watch.status(); } catch (Exception e) { return error(e); } }
    @Override public synchronized String stopWatch() { try { if (watch != null) watch.stop(); return status(); } catch (Exception e) { return error(e); } }
    @Override public String scanFiles(String json) {
        try { return FileProbe.scan(new JSONObject(json), "uid=" + Process.myUid()).toString(); }
        catch (Exception e) { return error(e); }
    }
    private String error(Exception e) {
        try { return new JSONObject().put("error", e.toString()).put("error_code", e instanceof F1Watch.Refused ? ((F1Watch.Refused)e).code : "f1_operation_failed").toString(); }
        catch (Exception ignored) { return "{\"error\":\"internal error\"}"; }
    }
}
