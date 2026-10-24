package tv.danmaku.bili;

import java.io.*;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;

/** Shared constraints for local evidence and portable export paths. */
final class EvidenceFiles {
    static final long MAX_IMAGE_BYTES = 8L * 1024 * 1024;
    static final long MAX_IMAGE_TOTAL = 128L * 1024 * 1024;
    static final int MAX_IMAGES = 128;
    static String folder(String run, long time, String nonce) {
        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.ROOT).format(new Date(time));
        return stamp + "_" + component(run) + "_" + component(nonce);
    }
    static String component(String value) {
        String s = value == null ? "" : value.replaceAll("[^A-Za-z0-9._-]", "_");
        if (s.isEmpty() || s.equals(".") || s.equals("..")) s = "unknown";
        return s.length() > 96 ? s.substring(0, 96) : s;
    }
    static File resolve(File filesDir, String reference) throws IOException {
        File root = new File(filesDir, "f6-ui").getCanonicalFile();
        File file = new File(filesDir, reference).getCanonicalFile();
        if (!file.getPath().startsWith(root.getPath() + File.separator)) throw new IOException("Invalid evidence reference");
        return file;
    }
    static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(file)) {
            byte[] bytes = new byte[8192]; int n;
            while ((n = in.read(bytes)) != -1) digest.update(bytes, 0, n);
        }
        StringBuilder out = new StringBuilder();
        for (byte b : digest.digest()) out.append(String.format(Locale.ROOT, "%02x", b & 255));
        return out.toString();
    }
}
