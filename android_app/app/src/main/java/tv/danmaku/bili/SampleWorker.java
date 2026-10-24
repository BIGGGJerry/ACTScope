package tv.danmaku.bili;
import android.content.Context;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
public class SampleWorker extends Worker {
    public SampleWorker(@NonNull Context c, @NonNull WorkerParameters p) { super(c, p); }
    @NonNull public Result doWork() {
        Context c = getApplicationContext();
        if (!ProbeConfig.prefs(c).getBoolean("sampling", false)) return Result.success();
        try { Telemetry.sample(c); Telemetry.upload(c); return Result.success(); }
        catch (Exception e) { UiStatus.telemetry(c, "status_sample_error", e.getMessage()); return Result.failure(); }
    }
}
