package tv.danmaku.bili;

import org.json.*;
import java.util.*;
import java.util.regex.Pattern;

/** The exact grammar used by the ten checked-in scripts, not the complete DroidBot engine. */
final class LegacyUiScript {
    final JSONObject document, config;
    private final Map<String, Integer> operationCounts = new HashMap<>();
    LegacyUiScript(JSONObject document, JSONObject config) throws Exception {
        this.document = document; this.config = config;
        JSONObject views = document.getJSONObject("views"), states = document.getJSONObject("states"), operations = document.getJSONObject("operations");
        Iterator<String> ids = views.keys();
        while (ids.hasNext()) {
            JSONObject selector = views.getJSONObject(ids.next()); Iterator<String> keys = selector.keys();
            while (keys.hasNext()) { String key = keys.next(); if (!Arrays.asList("text", "resource_id", "content_desc", "class").contains(key)) throw new IllegalArgumentException("Unsupported selector: " + key); Pattern.compile(selector.getString(key)); }
        }
        ids = states.keys();
        while (ids.hasNext()) { JSONObject state = states.getJSONObject(ids.next()); if (state.length() != 1 || !state.has("views")) throw new IllegalArgumentException("Unsupported state condition"); JSONArray refs = state.getJSONArray("views"); for (int i = 0; i < refs.length(); i++) views.getJSONObject(refs.getString(i)); }
        ids = operations.keys();
        while (ids.hasNext()) { JSONArray events = operations.getJSONArray(ids.next()); for (int i = 0; i < events.length(); i++) { JSONObject event = events.getJSONObject(i); String type = event.getString("event_type"); if ("touch".equals(type)) views.getJSONObject(event.getString("target_view")); else if (!"exit".equals(type)) throw new IllegalArgumentException("Unsupported event: " + type); } }
        JSONArray order = config.getJSONArray("state_order");
        for (int i = 0; i < order.length(); i++) { String state = order.getString(i); states.getJSONObject(state); JSONArray ops = document.getJSONObject("main").getJSONArray(state); for (int j = 0; j < ops.length(); j++) operations.getJSONArray(ops.getString(j)); }
    }
    static boolean matches(JSONObject selector, JSONObject node) throws Exception {
        if (!node.optBoolean("visible", false)) return false;
        Iterator<String> keys = selector.keys();
        while (keys.hasNext()) { String key = keys.next(); if (node.isNull(key) || !Pattern.compile(selector.getString(key)).matcher(node.optString(key, "")).lookingAt()) return false; }
        return true;
    }
    int find(String view, JSONArray nodes) throws Exception {
        JSONObject selector = document.getJSONObject("views").getJSONObject(view);
        for (int i = 0; i < nodes.length(); i++) if (matches(selector, nodes.getJSONObject(i))) return i;
        return -1;
    }
    boolean stateMatches(String state, JSONArray nodes) throws Exception {
        JSONArray views = document.getJSONObject("states").getJSONObject(state).getJSONArray("views");
        for (int i = 0; i < views.length(); i++) if (find(views.getString(i), nodes) < 0) return false;
        return true;
    }
    String manualBlock(JSONArray nodes) throws Exception {
        JSONObject blocked = config.getJSONObject("blocked_views"); Iterator<String> ids = blocked.keys();
        while (ids.hasNext()) { String view = ids.next(); if (document.getJSONObject("views").has(view) && find(view, nodes) >= 0) return view + ": " + blocked.getString(view); }
        return null;
    }
    JSONObject next(JSONArray nodes) throws Exception {
        String manual = manualBlock(nodes); if (manual != null) return new JSONObject().put("manual_reason", manual);
        JSONArray order = config.getJSONArray("state_order");
        for (int i = 0; i < order.length(); i++) {
            String state = order.getString(i); if (!stateMatches(state, nodes)) continue;
            JSONArray operations = document.getJSONObject("main").getJSONArray(state);
            int turn = operationCounts.containsKey(state) ? operationCounts.get(state) : 0;
            operationCounts.put(state, turn + 1);
            String operation = operations.getString(turn % operations.length());
            JSONArray events = document.getJSONObject("operations").getJSONArray(operation);
            return new JSONObject().put("state", state).put("operation", operation).put("events", events);
        }
        return null;
    }
    static boolean unsafeActionText(JSONObject node) {
        String text = (node.optString("text", "") + " " + node.optString("content_desc", "")).toLowerCase(Locale.ROOT);
        return Pattern.compile("同意|接受|登录|登入|注册|支付|购买|删除|清除|退出账号|\\b(sign in|log in|agree|accept|subscribe|purchase|delete)\\b").matcher(text).find();
    }
}
