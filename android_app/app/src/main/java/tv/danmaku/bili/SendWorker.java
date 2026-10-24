package tv.danmaku.bili;
import android.content.Context;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import org.json.JSONObject;
public class SendWorker extends Worker {
    public SendWorker(@NonNull Context c, @NonNull WorkerParameters p) { super(c, p); }
    @NonNull public Result doWork() {
        try (TelemetryStore db = new TelemetryStore(getApplicationContext())) {
            for (int n = 0; n < 100 && !isStopped(); n++) {
                JSONObject row = db.next(); if (row == null) return Result.success();
                JSONObject ack = Network.request(row.getString("endpoint") + "/v1/telemetry", row.getString("token"), row.getString("payload"));
                if (!ack.optBoolean("accepted", false) || !ack.has("received_at_server")) throw new java.io.IOException("Missing telemetry acknowledgement");
                db.sent(row.getLong("sequence"), ack.getLong("received_at_server"));
            }
            return db.queued() == 0 ? Result.success() : Result.retry();
        } catch (Exception e) { UiStatus.telemetry(getApplicationContext(), "status_upload_pending", e.getMessage()); return Result.retry(); }
    }
}
