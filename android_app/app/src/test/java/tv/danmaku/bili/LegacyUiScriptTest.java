package tv.danmaku.bili;

import org.json.*;
import org.junit.Test;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;
import static org.junit.Assert.*;

public class LegacyUiScriptTest {
    private JSONObject read(String path) throws Exception { return new JSONObject(new String(Files.readAllBytes(new File(System.getProperty("actscope.assets"), path).toPath()), StandardCharsets.UTF_8)); }
    private JSONObject node(String text, String id, String cls, String description) throws Exception { return new JSONObject().put("visible", true).put("text", text).put("resource_id", id).put("class", cls).put("content_desc", description); }
    private JSONObject config(String name) throws Exception { JSONArray targets = read("f6/catalog.json").getJSONArray("targets"); for (int i = 0; i < targets.length(); i++) if (targets.getJSONObject(i).getString("name").equals(name)) return targets.getJSONObject(i); throw new AssertionError(name); }
    @Test public void allTenOriginalScriptsValidateAndRemainByteIdenticalToManifest() throws Exception {
        JSONArray targets = read("f6/catalog.json").getJSONArray("targets"); assertEquals(10, targets.length());
        int touch = 0, exit = 0;
        for (int i = 0; i < targets.length(); i++) {
            JSONObject cfg = targets.getJSONObject(i), doc = read(cfg.getString("script_asset")); new LegacyUiScript(doc, cfg);
            byte[] raw = Files.readAllBytes(new File(System.getProperty("actscope.assets"), cfg.getString("script_asset")).toPath());
            assertEquals(cfg.getString("source_sha256"), FileProbe.hex(MessageDigest.getInstance("SHA-256").digest(raw)));
            JSONObject ops = doc.getJSONObject("operations"); Iterator<String> keys = ops.keys();
            while (keys.hasNext()) { JSONArray events = ops.getJSONArray(keys.next()); for (int j = 0; j < events.length(); j++) { String type = events.getJSONObject(j).getString("event_type"); if (type.equals("touch")) touch++; else if(type.equals("exit")) exit++; } }
        }
        assertEquals(38, touch); assertEquals(23, exit);
    }
    @Test public void builtInFileRulesAreCompleteAndPackageQueriesAreExplicit() throws Exception {
        JSONObject rules = read("f6/file_rules.json"); assertEquals(188, rules.getJSONArray("rule_manifest").length());
        String manifest = new String(Files.readAllBytes(new File(System.getProperty("actscope.manifest")).toPath()), StandardCharsets.UTF_8);
        JSONArray targets = read("f6/catalog.json").getJSONArray("targets");
        for (int i = 0; i < targets.length(); i++) { JSONArray packages = targets.getJSONObject(i).getJSONArray("packages"); for (int j = 0; j < packages.length(); j++) assertTrue(manifest.contains("<package android:name=\"" + packages.getJSONObject(j).getString("package") + "\"")); }
    }
    @Test public void selectorsUsePythonRegexPrefixSemanticsAndAllFourFields() throws Exception {
        JSONObject selector = new JSONObject().put("text", "历史").put("resource_id", ".*history").put("class", ".*TextView").put("content_desc", "查看.*");
        JSONObject n = node("历史记录", "app:id/history", "android.widget.TextView", "查看历史");
        assertTrue(LegacyUiScript.matches(selector, n)); n.put("class", "android.widget.Button"); assertFalse(LegacyUiScript.matches(selector, n));
        n.put("class", "android.widget.TextView").put("visible", false); assertFalse(LegacyUiScript.matches(selector, n));
    }
    @Test public void stateNeedsEveryViewAndRespectsOriginalPriority() throws Exception {
        LegacyUiScript script = new LegacyUiScript(read("f6/ui/uc.json"), config("uc"));
        JSONArray nodes = new JSONArray().put(node("", "", "android.widget.RelativeLayout", "菜单"));
        assertFalse(script.stateMatches("main_state", nodes)); nodes.put(node("搜索", "", "android.widget.Button", ""));
        assertTrue(script.stateMatches("main_state", nodes)); assertEquals("main_operation", script.next(nodes).getString("operation"));
        nodes.put(node("收藏/历史", "", "android.widget.TextView", "")); assertEquals("his_operation", script.next(nodes).getString("operation"));
    }
    @Test public void consentAndLoginNeverRunWhileSafeDialogCloseRemainsAvailable() throws Exception {
        LegacyUiScript qq = new LegacyUiScript(read("f6/ui/qq.json"), config("qq"));
        JSONArray login = new JSONArray().put(node("", "com.tencent.mobileqq:id/n6v", "android.widget.Button", ""));
        assertTrue(qq.next(login).has("manual_reason"));
        LegacyUiScript browser = new LegacyUiScript(read("f6/ui/qqbrowser.json"), config("qqbrowser"));
        JSONArray close = new JSONArray().put(node("立即登录", "com.tencent.mtt:id/title", "android.widget.TextView", ""))
            .put(node("", "com.tencent.mtt:id/btn", "android.widget.ImageView", "关闭按钮"));
        assertEquals("login_operation", browser.next(close).getString("operation"));
        assertFalse(LegacyUiScript.unsafeActionText(close.getJSONObject(1)));
        JSONArray consent = new JSONArray().put(node("确认", "", "android.widget.Button", ""));
        assertTrue(browser.next(consent).has("manual_reason"));
    }
    @Test public void unsupportedGrammarStopsRatherThanSilentlyIgnoring() throws Exception {
        JSONObject doc = read("f6/ui/uc.json"); doc.getJSONObject("views").getJSONObject("menu").put("in_coordinates", new JSONArray());
        try { new LegacyUiScript(doc, config("uc")); fail("Unsupported syntax must fail closed"); } catch (IllegalArgumentException expected) { assertTrue(expected.getMessage().contains("Unsupported")); }
    }
    @Test public void sideEffectLabelsAreNeverTreatedAsSafeNavigation() throws Exception {
        for (String text : Arrays.asList("同意", "立即登录", "清除记录", "删除历史", "购买", "Sign in")) assertTrue(LegacyUiScript.unsafeActionText(node(text,"","", "")));
        assertFalse(LegacyUiScript.unsafeActionText(node("历史", "", "", "关闭按钮")));
    }
}
