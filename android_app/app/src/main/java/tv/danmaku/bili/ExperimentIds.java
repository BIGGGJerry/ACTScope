package tv.danmaku.bili;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;

final class ExperimentIds {
    static boolean valid(String id) { return id != null && id.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,95}"); }
    static String local() { return "local-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(new Date()) + "-" + UUID.randomUUID().toString().substring(0, 8); }
}
