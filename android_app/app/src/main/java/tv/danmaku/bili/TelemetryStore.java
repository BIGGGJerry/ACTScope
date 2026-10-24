package tv.danmaku.bili;

import android.content.Context;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import org.json.JSONArray;
import org.json.JSONObject;

final class TelemetryStore extends SQLiteOpenHelper {
    TelemetryStore(Context c) { super(c, "telemetry.db", null, 1); }
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE queue (sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT, endpoint TEXT NOT NULL, token TEXT NOT NULL)");
        db.execSQL("CREATE TABLE history (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, uploaded_at INTEGER, received_at_server INTEGER)");
    }
    public void onUpgrade(SQLiteDatabase db, int a, int b) { throw new IllegalStateException("No destructive migrations"); }
    long enqueue(JSONObject event, JSONObject cfg) throws Exception {
        SQLiteDatabase db = getWritableDatabase(); db.beginTransaction();
        try {
            try (Cursor c = db.rawQuery("SELECT count(*) FROM queue", null)) { c.moveToFirst(); if (c.getLong(0) >= 10000) throw new IllegalStateException("Queue full; export/restore network before continuing"); }
            ContentValues row = new ContentValues(); row.put("endpoint", cfg.getString("endpoint")); row.put("token", cfg.getString("token"));
            long seq = db.insertOrThrow("queue", null, row); event.put("sequence", seq);
            row.clear(); row.put("payload", event.toString()); db.update("queue", row, "sequence=?", new String[]{"" + seq});
            row.put("sequence", seq); db.insertOrThrow("history", null, row);
            db.setTransactionSuccessful(); return seq;
        } finally { db.endTransaction(); }
    }
    JSONObject next() throws Exception {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT sequence,payload,endpoint,token FROM queue ORDER BY sequence LIMIT 1", null)) {
            if (!c.moveToFirst()) return null;
            return new JSONObject().put("sequence", c.getLong(0)).put("payload", c.getString(1)).put("endpoint", c.getString(2)).put("token", c.getString(3));
        }
    }
    void sent(long seq, long receivedAtServer) {
        SQLiteDatabase db = getWritableDatabase(); db.beginTransaction();
        try { ContentValues v = new ContentValues(); v.put("uploaded_at", System.currentTimeMillis()); v.put("received_at_server", receivedAtServer); db.update("history", v, "sequence=?", new String[]{"" + seq}); db.delete("queue", "sequence=?", new String[]{"" + seq}); db.setTransactionSuccessful(); }
        finally { db.endTransaction(); }
    }
    long queued() { try (Cursor c = getReadableDatabase().rawQuery("SELECT count(*) FROM queue", null)) { c.moveToFirst(); return c.getLong(0); } }
    JSONArray export() throws Exception {
        JSONArray out = new JSONArray();
        try (Cursor c = getReadableDatabase().rawQuery("SELECT payload,uploaded_at,received_at_server FROM history ORDER BY sequence", null)) {
            while (c.moveToNext()) out.put(new JSONObject().put("event", new JSONObject(c.getString(0))).put("uploaded_at_local", c.isNull(1) ? JSONObject.NULL : c.getLong(1)).put("received_at_server", c.isNull(2) ? JSONObject.NULL : c.getLong(2)));
        }
        return out;
    }
}
