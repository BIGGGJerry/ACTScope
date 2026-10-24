package tv.danmaku.bili;

import org.junit.Test;
import org.json.JSONObject;
import java.io.File;
import java.util.*;
import java.util.regex.*;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.NodeList;
import static org.junit.Assert.*;

public class LocalizedResourcesTest {
    private Map<String,String> read(String locale) throws Exception {
        File source = new File(System.getProperty("actscope.resources"), locale + "/strings.xml");
        NodeList strings = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(source).getElementsByTagName("string");
        Map<String,String> out = new TreeMap<>();
        for (int n = 0; n < strings.getLength(); n++) out.put(strings.item(n).getAttributes().getNamedItem("name").getNodeValue(), strings.item(n).getTextContent());
        return out;
    }
    @Test public void allUiMessagesHaveBothChineseAndEnglishResources() throws Exception {
        Map<String,String> en = read("values"), zh = read("values-zh"); assertEquals(en.keySet(), zh.keySet());
        Map<String,String> hant = read("values-b+zh+Hant"); assertEquals(en.keySet(), hant.keySet());
        assertTrue(en.get("f6_start").startsWith("One-tap")); assertTrue(zh.get("f6_start").startsWith("一键"));
        assertTrue(hant.get("f6_start").startsWith("一鍵"));
        assertTrue(zh.get("f6_needs_a11y").contains("无障碍"));
    }
    @Test public void translatedDynamicMessagesKeepFormattingCompatible() throws Exception {
        Map<String,String> en = read("values"), zh = read("values-zh"), hant = read("values-b+zh+Hant"); Pattern p = Pattern.compile("%([0-9]+)\\$([sd])");
        for (String key : en.keySet()) {
            List<String> first = new ArrayList<>(), second = new ArrayList<>(); Map<Integer,Object> args = new TreeMap<>();
            Matcher a = p.matcher(en.get(key)), b = p.matcher(zh.get(key));
            while (a.find()) { first.add(a.group()); args.put(Integer.parseInt(a.group(1)), a.group(2).equals("d") ? 1 : "test"); }
            while (b.find()) second.add(b.group());
            assertEquals(key, first, second);
            String.format(Locale.ENGLISH, en.get(key), args.values().toArray()); String.format(Locale.CHINESE, zh.get(key), args.values().toArray());
            String.format(Locale.TRADITIONAL_CHINESE, hant.get(key), args.values().toArray());
        }
    }
    @Test public void persistentStatusRetainsMessageIdentityAndNumericArguments() throws Exception {
        JSONObject message = new JSONObject(UiStatus.encode("f6_ui_progress", 1, 2, 3, 4));
        assertEquals("f6_ui_progress", message.getString("message")); assertEquals(4, message.getJSONArray("args").getInt(3));
        assertFalse(message.toString().contains("completed"));
    }
}
