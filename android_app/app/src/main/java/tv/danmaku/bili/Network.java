package tv.danmaku.bili;

import org.json.JSONObject;
import java.io.*;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import java.nio.charset.StandardCharsets;

final class Network {
    static JSONObject request(String url, String token, String body) throws Exception {
        URL target = new URL(url);
        if (!"https".equalsIgnoreCase(target.getProtocol())) throw new IOException("HTTPS required");
        HttpsURLConnection c = (HttpsURLConnection) target.openConnection();
        c.setConnectTimeout(8000); c.setReadTimeout(8000); c.setInstanceFollowRedirects(false);
        c.setRequestProperty("Accept", "application/json");
        if (token != null) c.setRequestProperty("Authorization", "Bearer " + token);
        try {
            if (body != null) {
                c.setRequestMethod("POST"); c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json");
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                c.setFixedLengthStreamingMode(bytes.length);
                try (OutputStream out = c.getOutputStream()) { out.write(bytes); }
            }
            int status = c.getResponseCode();
            if (status < 200 || status >= 300) throw new IOException("HTTP " + status);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = c.getInputStream()) {
                byte[] b = new byte[1024]; int n;
                while ((n = in.read(b)) != -1) { out.write(b, 0, n); if (out.size() > 65536) throw new IOException("Response too large"); }
            }
            String text = new String(out.toByteArray(), StandardCharsets.UTF_8);
            return text.trim().isEmpty() ? new JSONObject() : new JSONObject(text);
        } finally { c.disconnect(); }
    }
}
