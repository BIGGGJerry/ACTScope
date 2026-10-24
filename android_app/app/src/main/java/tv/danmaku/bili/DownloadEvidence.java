package tv.danmaku.bili;

import android.content.*;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import org.json.JSONObject;
import java.io.*;
import java.util.*;

/** Publishes new files under Download/ACTScope, never overwriting an earlier export. */
final class DownloadEvidence implements EvidencePackage.Sink, AutoCloseable {
    private final Context context;
    private final String folder;
    private final List<Uri> pending = new ArrayList<>();
    private final List<File> legacy = new ArrayList<>();
    private boolean committed;
    DownloadEvidence(Context context, String folder) { this.context = context; this.folder = folder; }
    static JSONObject export(Context context, JSONObject bundle) throws Exception {
        String folder = EvidenceFiles.folder(bundle.optString("run_id"), System.currentTimeMillis(), UUID.randomUUID().toString());
        try (DownloadEvidence sink = new DownloadEvidence(context, folder)) {
            JSONObject report = EvidencePackage.write(context.getFilesDir(), bundle, folder, sink);
            sink.commit(); return report;
        }
    }
    @Override public void write(String relative, String mime, InputStream input) throws Exception {
        if (relative.startsWith("/") || relative.contains("..") || !relative.matches("[A-Za-z0-9._/-]+")) throw new IOException("Invalid export path");
        if (Build.VERSION.SDK_INT >= 29) {
            int slash = relative.lastIndexOf('/');
            ContentValues values = new ContentValues();
            values.put(MediaStore.MediaColumns.DISPLAY_NAME, relative.substring(slash + 1));
            values.put(MediaStore.MediaColumns.MIME_TYPE, mime);
            values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/ACTScope/" + folder + "/" + (slash < 0 ? "" : relative.substring(0, slash + 1)));
            values.put(MediaStore.MediaColumns.IS_PENDING, 1);
            Uri uri = context.getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (uri == null) throw new IOException("Cannot create Download evidence file");
            pending.add(uri);
            try (OutputStream out = context.getContentResolver().openOutputStream(uri, "w")) {
                if (out == null) throw new IOException("Cannot write Download evidence file"); copy(input, out);
            }
        } else {
            File root = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "ACTScope/" + folder).getCanonicalFile();
            File file = new File(root, relative).getCanonicalFile();
            if (!file.getPath().startsWith(root.getPath() + File.separator)) throw new IOException("Invalid Download path");
            File parent = file.getParentFile();
            if (!parent.isDirectory() && !parent.mkdirs()) throw new IOException("Cannot create Download evidence folder");
            if (!file.createNewFile()) throw new IOException("Refusing to overwrite evidence");
            legacy.add(file);
            try (OutputStream out = new FileOutputStream(file)) { copy(input, out); }
        }
    }
    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] bytes = new byte[8192]; int n; while ((n = in.read(bytes)) != -1) out.write(bytes, 0, n);
    }
    private void commit() throws Exception {
        if (Build.VERSION.SDK_INT >= 29) {
            ContentValues values = new ContentValues(); values.put(MediaStore.MediaColumns.IS_PENDING, 0);
            for (Uri uri : pending) if (context.getContentResolver().update(uri, values, null, null) != 1) throw new IOException("Cannot publish evidence file");
        } else {
            String[] paths = new String[legacy.size()]; for (int i = 0; i < paths.length; i++) paths[i] = legacy.get(i).getAbsolutePath();
            MediaScannerConnection.scanFile(context, paths, null, null);
        }
        committed = true;
    }
    @Override public void close() {
        if (committed) return;
        for (Uri uri : pending) try { context.getContentResolver().delete(uri, null, null); } catch (Exception ignored) { }
        for (File file : legacy) file.delete();
    }
}
