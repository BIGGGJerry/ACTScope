package tv.danmaku.bili;

import android.accessibilityservice.AccessibilityService;
import android.graphics.Bitmap;
import android.hardware.HardwareBuffer;
import android.os.Build;
import android.os.Handler;
import android.os.SystemClock;
import android.view.Display;
import android.view.accessibility.AccessibilityNodeInfo;
import org.json.JSONObject;
import java.io.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Explicit F6 checkpoints only. Never captures screens for background telemetry. */
final class ScreenshotCapture {
    private final ProbeAccessibilityService service;
    private final Handler handler;
    // Keep one process-wide callback executor alive: the OS may deliver a late callback
    // after cancellation. Rejecting it could leak its HardwareBuffer or crash the service.
    private static final ExecutorService WRITER = Executors.newSingleThreadExecutor();
    private AtomicBoolean pending;
    private boolean closed;
    private long lastRequest;
    ScreenshotCapture(ProbeAccessibilityService service, Handler handler) { this.service = service; this.handler = handler; }
    void close() { closed = true; if (pending != null) pending.set(true); }
    static boolean targetVisible(AccessibilityService service, String target) {
        AccessibilityNodeInfo root = service.getRootInActiveWindow();
        if (root == null) return false;
        try { return target.contentEquals(root.getPackageName() == null ? "" : root.getPackageName()); }
        finally { root.recycle(); }
    }
    static JSONObject failure(String reason) {
        try { return new JSONObject().put("status", "unavailable").put("reason", reason).put("attempted_at_device", System.currentTimeMillis()); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
    void capture(String target, File output, Consumer<JSONObject> done) {
        if (Build.VERSION.SDK_INT < 30) { done.accept(failure("requires_android_11_accessibility_screenshot")); return; }
        long delay = Math.max(0, 350 - (SystemClock.elapsedRealtime() - lastRequest));
        if (delay > 0) handler.postDelayed(() -> request(target, output, done), delay);
        else request(target, output, done);
    }
    private void request(String target, File output, Consumer<JSONObject> done) {
        if (closed) { done.accept(failure("capture_cancelled")); return; }
        if (!targetVisible(service, target)) { done.accept(failure("foreground_package_mismatch")); return; }
        AtomicBoolean settled = new AtomicBoolean();
        pending = settled;
        Runnable timeout = () -> { if (settled.compareAndSet(false, true)) done.accept(failure("screenshot_timeout")); };
        handler.postDelayed(timeout, 5000);
        Consumer<JSONObject> finish = result -> handler.post(() -> {
            if (!settled.compareAndSet(false, true)) { output.delete(); return; }
            handler.removeCallbacks(timeout);
            if (!targetVisible(service, target)) { output.delete(); done.accept(failure("foreground_changed_during_capture")); }
            else done.accept(result);
        });
        try { lastRequest = SystemClock.elapsedRealtime(); Native.capture(service, WRITER, output, settled, finish); }
        catch (Exception e) { finish.accept(failure("screenshot_request_failed: " + e)); }
    }
    @android.annotation.TargetApi(30)
    private static final class Native {
        static void capture(AccessibilityService service, Executor executor, File output, AtomicBoolean settled, Consumer<JSONObject> finish) {
            service.takeScreenshot(Display.DEFAULT_DISPLAY, executor, new AccessibilityService.TakeScreenshotCallback() {
                @Override public void onSuccess(AccessibilityService.ScreenshotResult result) {
                    Bitmap hardware = null, bitmap = null;
                    try (HardwareBuffer buffer = result.getHardwareBuffer()) {
                        if (settled.get()) return;
                        hardware = Bitmap.wrapHardwareBuffer(buffer, result.getColorSpace());
                        if (hardware == null) throw new IOException("No screenshot bitmap");
                        bitmap = hardware.copy(Bitmap.Config.ARGB_8888, false);
                        if (bitmap == null) throw new IOException("Cannot copy screenshot bitmap");
                        try (OutputStream out = new LimitedOutput(new FileOutputStream(output), EvidenceFiles.MAX_IMAGE_BYTES)) {
                            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) throw new IOException("PNG encoding failed");
                        }
                        if (settled.get()) { output.delete(); return; }
                        finish.accept(new JSONObject().put("status", "saved").put("method", "accessibility_takeScreenshot")
                            .put("captured_at_device", System.currentTimeMillis()).put("screenshot_timestamp_uptime_ms", result.getTimestamp())
                            .put("width", bitmap.getWidth()).put("height", bitmap.getHeight())
                            .put("size_bytes", output.length()).put("sha256", EvidenceFiles.sha256(output)));
                    } catch (Exception e) { output.delete(); finish.accept(failure("screenshot_write_failed: " + e)); }
                    finally { if (bitmap != null) bitmap.recycle(); if (hardware != null) hardware.recycle(); }
                }
                @Override public void onFailure(int code) { finish.accept(failure("accessibility_screenshot_error_" + code)); }
            });
        }
    }
    private static final class LimitedOutput extends FilterOutputStream {
        private final long limit; private long size;
        LimitedOutput(OutputStream out, long limit) { super(out); this.limit = limit; }
        @Override public void write(int b) throws IOException { check(1); out.write(b); }
        @Override public void write(byte[] b, int off, int len) throws IOException { check(len); out.write(b, off, len); }
        private void check(int amount) throws IOException { if (size + amount > limit) throw new IOException("Screenshot exceeds 8MiB"); size += amount; }
    }
}
