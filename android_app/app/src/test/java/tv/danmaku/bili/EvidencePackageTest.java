package tv.danmaku.bili;

import org.json.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import static org.junit.Assert.*;

public class EvidencePackageTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private File root;
    private final Map<String,byte[]> written = new LinkedHashMap<>();
    private EvidencePackage.Sink sink;
    @Before public void setup() throws Exception {
        root = temp.newFolder("files");
        sink = (path, mime, input) -> { assertFalse(written.containsKey(path)); ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] b = new byte[128]; int n; while ((n = input.read(b)) != -1) out.write(b, 0, n); written.put(path, out.toByteArray()); };
    }
    private JSONObject state(String pkg, String ref) throws Exception {
        JSONObject state = new JSONObject().put("target_package", pkg).put("reason", "before_touch");
        if (ref != null) {
            File image = new File(root, ref); image.getParentFile().mkdirs();
            Files.write(image.toPath(), new byte[]{(byte)137, 80, 78, 71, 13, 10, 26, 10});
            state.put("screenshot", new JSONObject().put("status", "saved").put("evidence_ref", ref).put("size_bytes", image.length()).put("sha256", EvidenceFiles.sha256(image)));
        }
        return new JSONObject().put("evidence_ref", "f6-ui/run/batch/state.json").put("content", state);
    }
    private JSONObject bundle(JSONObject... states) throws Exception {
        return new JSONObject().put("run_id", "test-run").put("ui_evidence", new JSONArray(Arrays.asList(states))).put("ui_evidence_export", new JSONObject().put("truncated", false));
    }
    @Test public void exportsImagesAndStateJsonPerAppWithPortableReferences() throws Exception {
        JSONObject first = state("com.example.one", "f6-ui/run/batch/one.png"), second = state("com.example.two", "f6-ui/run/batch/two.png");
        JSONObject report = EvidencePackage.write(root, bundle(first, second), "unique", sink);
        assertEquals(2, report.getInt("screenshots_exported")); assertTrue(report.getBoolean("evidence_export_complete"));
        assertTrue(written.containsKey("apps/com.example.one/0001_before_touch.png"));
        assertTrue(written.containsKey("apps/com.example.two/0002_before_touch.json"));
        JSONObject exported = new JSONObject(new String(written.get("actscope-device-evidence.json"), StandardCharsets.UTF_8));
        assertEquals("apps/com.example.one/0001_before_touch.png", exported.getJSONArray("ui_evidence").getJSONObject(0).getJSONObject("content").getJSONObject("screenshot").getString("export_relative_path"));
    }
    @Test public void oldResultsAreExportedWithoutInventingScreenshots() throws Exception {
        JSONObject report = EvidencePackage.write(root, bundle(state("com.old.app", null)), "old", sink);
        assertEquals(0, report.getInt("screenshots_exported")); assertEquals(1, report.getInt("screenshots_unavailable")); assertFalse(report.getBoolean("evidence_export_complete"));
        assertTrue(written.containsKey("actscope-device-evidence.json"));
    }
    @Test public void hashMismatchIsReportedWithoutCopyingImage() throws Exception {
        JSONObject item = state("com.test", "f6-ui/run/a.png"); item.getJSONObject("content").getJSONObject("screenshot").put("sha256", "wrong");
        JSONObject report = EvidencePackage.write(root, bundle(item), "hash", sink);
        assertEquals(1, report.getInt("screenshots_unavailable")); assertEquals(2, written.size());
        assertTrue(report.getJSONArray("diagnostics").toString().contains("hash mismatch"));
    }
    @Test public void fileOutsideEvidenceRootCannotBeExported() throws Exception {
        JSONObject item = state("com.test", "f6-ui/run/a.png"); item.getJSONObject("content").getJSONObject("screenshot").put("evidence_ref", "../outside.png");
        JSONObject report = EvidencePackage.write(root, bundle(item), "scope", sink);
        assertEquals(0, report.getInt("screenshots_exported")); assertTrue(report.getJSONArray("diagnostics").toString().contains("Invalid evidence reference"));
    }
    @Test public void imageWriteFailureAbortsInsteadOfPublishingPartialSuccess() throws Exception {
        try {
            EvidencePackage.write(root, bundle(state("com.test", "f6-ui/run/a.png")), "failed", (path, mime, input) -> { throw new IOException("disk full"); }); fail("Must abort");
        } catch (IOException expected) { assertEquals("disk full", expected.getMessage()); }
    }
    @Test public void repeatedExportNamesDoNotCollideOrContainDirectoryTraversal() {
        String a = EvidenceFiles.folder("../../test", 0, "id-one"), b = EvidenceFiles.folder("../../test", 0, "id-two");
        assertFalse(a.contains("/")); assertNotEquals(a, b); assertEquals("unknown", EvidenceFiles.component(".."));
    }
    @Test public void truncatedUiExportRemainsIncompleteEvenIfAllAvailableImagesCopy() throws Exception {
        JSONObject bundle = bundle(state("com.test", "f6-ui/run/a.png")); bundle.getJSONObject("ui_evidence_export").put("truncated", true);
        JSONObject report = EvidencePackage.write(root, bundle, "truncated", sink);
        assertEquals(1, report.getInt("screenshots_exported")); assertFalse(report.getBoolean("evidence_export_complete"));
    }
    @Test public void corruptPngIsNotExportedEvenWithMatchingHash() throws Exception {
        JSONObject item = state("com.test", "f6-ui/run/a.png"); File file = new File(root, "f6-ui/run/a.png"); Files.write(file.toPath(), new byte[8]);
        item.getJSONObject("content").getJSONObject("screenshot").put("sha256", EvidenceFiles.sha256(file));
        JSONObject report = EvidencePackage.write(root, bundle(item), "corrupt", sink);
        assertEquals(0, report.getInt("screenshots_exported"));
    }
}
