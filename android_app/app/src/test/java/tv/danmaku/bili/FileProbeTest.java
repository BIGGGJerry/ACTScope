package tv.danmaku.bili;

import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.json.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import static org.junit.Assert.*;

public class FileProbeTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private File file(String name, String body) throws Exception { File f = temp.newFile(name); Files.write(f.toPath(), body.getBytes(StandardCharsets.UTF_8)); return f; }
    @Test public void rejectsForeignApkBeforeWriting() throws Exception {
        File owned = file("original.apk", "owned original"), foreign = file("foreign.apk", "someone else"), replacement = file("replacement.apk", "test replacement");
        String originalHash = FileProbe.sha256(owned); byte[] bytes = FileProbe.controlledReplacement(replacement, FileProbe.sha256(replacement));
        assertFalse(FileProbe.replaceOwned(foreign, originalHash, bytes));
        assertEquals("someone else", new String(Files.readAllBytes(foreign.toPath()), StandardCharsets.UTF_8));
        assertTrue(FileProbe.replaceOwned(owned, originalHash, bytes));
        assertEquals(FileProbe.sha256(replacement), FileProbe.sha256(owned));
    }
    @Test public void invalidReplacementHashFailsBeforeWrite() throws Exception {
        File replacement = file("B.apk", "test B");
        try { FileProbe.controlledReplacement(replacement, new String(new char[64]).replace("\0", "0")); fail("must reject changed replacement"); }
        catch (IllegalArgumentException expected) { assertTrue(expected.getMessage().contains("mismatch")); }
    }
    @Test public void doesNotTraverseSymlinkToOutsideScope() throws Exception {
        File root = temp.newFolder("root"); File outside = file("outside.txt", "private");
        Files.createSymbolicLink(new File(root, "link").toPath(), outside.toPath());
        JSONObject cfg = new JSONObject().put("roots", new JSONArray().put(root.getAbsolutePath()));
        JSONObject result = FileProbe.scan(cfg, "test"); assertEquals(0, result.getJSONArray("files").length());
    }
    @Test public void fileMetadataIsNotAutomaticResidueAttribution() throws Exception {
        file("sample.dat", "old data");
        JSONObject cfg = new JSONObject().put("roots", new JSONArray().put(temp.getRoot().getAbsolutePath()));
        JSONObject result = FileProbe.scan(cfg, "test"); JSONObject row = result.getJSONArray("files").getJSONObject(0);
        assertTrue(row.getBoolean("exists")); assertFalse(row.getBoolean("expected_cleanup")); assertFalse(row.getBoolean("attributed_to_prior_session")); assertTrue(row.isNull("public_resource"));
        assertTrue(result.getBoolean("file_scan_complete"));
    }
    @Test public void truncatedScanCannotClaimComplete() throws Exception {
        file("one.dat", "one"); file("two.dat", "two");
        JSONObject cfg = new JSONObject().put("roots", new JSONArray().put(temp.getRoot().getAbsolutePath())).put("max_results", 1);
        JSONObject result = FileProbe.scan(cfg, "test"); assertTrue(result.getBoolean("results_truncated")); assertFalse(result.getBoolean("file_scan_complete"));
    }
    @Test public void missingScopeReportedAsError() throws Exception {
        JSONObject cfg = new JSONObject().put("roots", new JSONArray().put(new File(temp.getRoot(), "missing").getAbsolutePath()));
        JSONObject result = FileProbe.scan(cfg, "test"); assertFalse(result.getBoolean("file_scan_complete")); assertEquals(1, result.getJSONArray("access_errors").length());
    }
    @Test public void expiredScanDeadlineStopsTraversalAndRecordsCoverageError() throws Exception {
        File data = file("data.txt", "owned data"); JSONArray errors = new JSONArray();
        FileProbe.walk(Arrays.asList(data), 100, errors, f -> fail("Expired scan must not execute a file visitor"), System.nanoTime() - 1);
        assertEquals(1, errors.length()); assertEquals("scan_timeout_reached", errors.getJSONObject(0).getString("reason"));
    }
    private JSONObject rule(File path, String kind, int line) throws Exception {
        return new JSONObject().put("path", path.getAbsolutePath()).put("kind", kind).put("app", "TestApp")
            .put("source", "rules/TestApp.txt").put("line", line);
    }
    @Test public void exactTerminalFileRuleRetainsSourceAndLine() throws Exception {
        File data = file("history.db", "owned test database");
        JSONObject cfg = new JSONObject().put("roots", new JSONArray().put(data.getAbsolutePath()))
            .put("rule_manifest", new JSONArray().put(rule(data, "file", 23)));
        JSONObject row = FileProbe.scan(cfg, "test").getJSONArray("files").getJSONObject(0);
        assertEquals(data.getCanonicalPath(), row.getString("path"));
        assertEquals(23, row.getInt("rule_line")); assertEquals("rules/TestApp.txt", row.getString("rule_source"));
        assertEquals("TestApp", row.getString("app")); assertEquals("file", row.getString("rule_kind"));
    }
    @Test public void directoryRuleCoversDescendantFilesAndReportsEmptyDirectory() throws Exception {
        File root = temp.newFolder("cache"); File child = new File(root, "result.json"); Files.write(child.toPath(), new byte[]{1});
        File empty = temp.newFolder("empty");
        JSONObject cfg = new JSONObject().put("roots", new JSONArray().put(root.getAbsolutePath()).put(empty.getAbsolutePath()))
            .put("rule_manifest", new JSONArray().put(rule(root, "directory", 10)).put(rule(empty, "directory", 11)));
        JSONObject result = FileProbe.scan(cfg, "test"); assertEquals(1, result.getJSONArray("files").length());
        JSONObject row = result.getJSONArray("files").getJSONObject(0);
        assertEquals(child.getAbsolutePath(), row.getString("path")); assertEquals("directory", row.getString("rule_kind")); assertEquals(10, row.getInt("rule_line"));
        assertEquals(2, result.getJSONArray("rule_observations").length());
        assertTrue(result.getBoolean("file_scan_complete"));
    }
    @Test public void f6AcceptsMoreThanSixteenRulesAndKeepsEveryMissingObservation() throws Exception {
        JSONArray roots = new JSONArray(), manifest = new JSONArray();
        for (int n = 0; n < 188; n++) { File path = new File(temp.getRoot(), "missing" + n); roots.put(path.getAbsolutePath()); manifest.put(rule(path, "file", n + 1)); }
        JSONObject result = FileProbe.scan(new JSONObject().put("roots", roots).put("rule_manifest", manifest), "test");
        assertEquals(188, result.getJSONArray("access_errors").length()); assertEquals(188, result.getJSONArray("rule_observations").length());
        assertFalse(result.getBoolean("file_scan_complete"));
        assertEquals("missing_or_inaccessible", result.getJSONArray("access_errors").getJSONObject(187).getString("reason"));
        assertEquals(188, result.getJSONArray("access_errors").getJSONObject(187).getInt("rule_line"));
    }
    @Test public void f1StillRejectsMoreThanSixteenRoots() throws Exception {
        JSONArray roots = new JSONArray(); for (int n = 0; n < 17; n++) roots.put(new File(temp.getRoot(), "root" + n).getAbsolutePath());
        try { FileProbe.roots(new JSONObject().put("roots", roots)); fail("F1 must retain its sixteen-root limit"); }
        catch (IllegalArgumentException expected) { assertTrue(expected.getMessage().contains("16")); }
    }
    @Test public void terminalFileRuleDoesNotExpandUnexpectedDirectory() throws Exception {
        File unexpected = temp.newFolder("should-be-file"); Files.write(new File(unexpected, "hidden.txt").toPath(), new byte[]{1});
        JSONObject cfg = new JSONObject().put("roots", new JSONArray().put(unexpected.getAbsolutePath()))
            .put("rule_manifest", new JSONArray().put(rule(unexpected, "file", 1)));
        JSONObject result = FileProbe.scan(cfg, "test"); assertEquals(0, result.getJSONArray("files").length()); assertFalse(result.getBoolean("file_scan_complete"));
        assertTrue(result.getJSONArray("access_errors").getJSONObject(0).getString("reason").contains("rule_kind_mismatch"));
    }
}
