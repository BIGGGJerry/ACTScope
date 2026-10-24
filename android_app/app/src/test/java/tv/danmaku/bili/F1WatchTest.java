package tv.danmaku.bili;

import org.json.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import java.io.*;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.Assert.*;

public class F1WatchTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private final byte[] a = "user original".getBytes(StandardCharsets.UTF_8), b = "passive replacement B".getBytes(StandardCharsets.UTF_8);
    private final List<F1Watch> watches = new ArrayList<>();
    private JSONObject config() throws Exception {
        return new JSONObject().put("roots", new JSONArray().put(temp.getRoot().getCanonicalPath()))
            .put("replacement_sha256", FileProbe.digest(new ByteArrayInputStream(b))).put("replacement_poll_ms", 10)
            .put("replacement_window_seconds", 2).put("run_id", "unit-f1").put("instance_id", "instance").put("build_id", "test-build");
    }
    private F1Watch monitor(JSONObject config) throws Exception { F1Watch watch = new F1Watch(config, b, "test"); watches.add(watch); return watch; }
    private F1Watch monitor() throws Exception { return monitor(config()); }
    private File put(String name, byte[] bytes) throws Exception { File f = new File(temp.getRoot(), name); Files.write(f.toPath(), bytes); return f; }
    private JSONObject status(F1Watch watch) throws Exception { return new JSONObject(watch.status()); }
    private JSONObject row(F1Watch watch) throws Exception { return status(watch).getJSONArray("candidates").getJSONObject(0); }
    private JSONObject arm(F1Watch watch, JSONObject row) throws Exception { return new JSONObject(watch.attempt(status(watch).getString("watch_id"), row.getString("candidate_id"))); }
    private interface Check { boolean get() throws Exception; }
    private void await(Check check) throws Exception {
        long end = System.nanoTime() + 4000000000L;
        while (!check.get() && System.nanoTime() < end) Thread.sleep(10);
        assertTrue("Timed out waiting for target-path worker", check.get());
    }
    private void finished(F1Watch watch, String state) throws Exception {
        await(() -> !status(watch).getBoolean("replacement_running")); assertEquals(state, status(watch).getString("replacement_state"));
    }
    private void disappeared(F1Watch watch) throws Exception {
        await(() -> status(watch).getJSONObject("pending_replacement").getBoolean("target_absent_observed"));
    }
    @After public void stopWorkers() throws Exception {
        for (F1Watch watch : watches) { watch.stop(); await(() -> !watch.isRunning()); }
    }
    @Test public void scanningNeverWritesAndRequiresNoAIdentity() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", new byte[]{3,4}); watch.scanOnce(false);
        assertArrayEquals(new byte[]{3,4}, Files.readAllBytes(target.toPath())); assertEquals("ready", row(watch).getString("status"));
        assertFalse(status(watch).getBoolean("replacement_attempted")); assertTrue(status(watch).isNull("original_sha256"));
    }
    @Test public void baselineApkIsNotAutomaticallyACandidate() throws Exception {
        put("old.apk", a); F1Watch watch = monitor(); watch.scanOnce(true); watch.scanOnce(false);
        assertEquals(1, status(watch).getInt("initial_apk_count")); assertEquals(0, status(watch).getJSONArray("candidates").length());
    }
    @Test public void clickingOnlyArmsAndLeavesExistingApkUntouched() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false);
        JSONObject armed = arm(watch, row(watch)); Thread.sleep(100);
        assertTrue(armed.getBoolean("replacement_running")); assertEquals("waiting_for_next_upload", status(watch).getString("replacement_state"));
        assertArrayEquals(a, Files.readAllBytes(target.toPath())); assertFalse(status(watch).getBoolean("replacement_attempted"));
    }
    @Test public void deletedCandidateCanBeArmedAndNewUploadIsReplaced() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); Files.delete(target.toPath()); watch.scanOnce(false);
        assertEquals("disappeared", row(watch).getString("status")); arm(watch, row(watch));
        byte[] uploaded = new byte[]{8,9,10}; Files.write(target.toPath(), uploaded); finished(watch, "succeeded");
        JSONObject outcome = status(watch), action = outcome.getJSONObject("last_attempt");
        assertArrayEquals(b, Files.readAllBytes(target.toPath())); assertTrue(action.getBoolean("replacement_succeeded"));
        assertEquals(FileProbe.digest(new ByteArrayInputStream(uploaded)), action.getString("original_sha256"));
        assertEquals("fresh_target_before_write", outcome.getString("original_identity_source"));
        assertFalse(outcome.getBoolean("install_completed")); assertFalse(outcome.getBoolean("installed_identity_verified")); assertFalse(outcome.getBoolean("observation_complete"));
    }
    @Test public void rewriteAtSamePathAfterArmTriggersReplacement() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); arm(watch, row(watch));
        Files.write(target.toPath(), new byte[]{7,6,5,4}); finished(watch, "succeeded");
        assertArrayEquals(b, Files.readAllBytes(target.toPath())); assertEquals("rewritten_apk_in_directory", status(watch).getJSONObject("last_attempt").getString("trigger"));
    }
    @Test public void disappearanceAndReappearanceOfSameBytesTriggersReplacement() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); arm(watch, row(watch));
        Files.delete(target.toPath()); disappeared(watch); Files.write(target.toPath(), a); finished(watch, "succeeded");
        assertArrayEquals(b, Files.readAllBytes(target.toPath())); assertEquals("new_apk_in_directory", status(watch).getJSONObject("last_attempt").getString("trigger"));
    }
    @Test public void unchangedFileTimesOutWithoutBeingWritten() throws Exception {
        F1Watch watch = monitor(config().put("replacement_window_seconds", 1)); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); arm(watch, row(watch));
        finished(watch, "timed_out"); assertArrayEquals(a, Files.readAllBytes(target.toPath())); assertFalse(status(watch).getBoolean("replacement_attempted"));
    }
    @Test public void stoppingCancelsWaitAndDoesNotWriteLaterUpload() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); arm(watch, row(watch)); watch.stop(); finished(watch, "cancelled");
        Files.write(target.toPath(), new byte[]{1,2}); Thread.sleep(60); assertArrayEquals(new byte[]{1,2}, Files.readAllBytes(target.toPath()));
    }
    @Test public void apkSymlinkIsSkippedAndCannotWriteAnotherFile() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); arm(watch, row(watch));
        File other = put("other.bin", a); Files.delete(target.toPath()); Files.createSymbolicLink(target.toPath(), other.toPath());
        await(() -> status(watch).getJSONObject("pending_replacement").getInt("excluded_symlinks") == 1);
        assertArrayEquals(a, Files.readAllBytes(other.toPath())); assertFalse(status(watch).getBoolean("replacement_attempted"));
        File next = put("next.apk", a); finished(watch, "succeeded"); assertArrayEquals(b, Files.readAllBytes(next.toPath()));
        assertArrayEquals(a, Files.readAllBytes(other.toPath()));
    }
    @Test public void oldWatchIdCannotArmCurrentMonitor() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); put("upload.apk", a); watch.scanOnce(false);
        try { watch.attempt("old-watch", row(watch).getString("candidate_id")); fail("Must refuse"); }
        catch (F1Watch.Refused expected) { assertEquals("watch_changed", expected.code); }
    }
    @Test public void oldCandidateIdCannotArmAfterPathRecordChanges() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); JSONObject selected = row(watch);
        Files.write(target.toPath(), new byte[]{1,2}); watch.scanOnce(false);
        try { arm(watch, selected); fail("Old selection must not be used"); } catch (F1Watch.Refused expected) { assertEquals("candidate_changed", expected.code); }
    }
    @Test public void secondArmIsRefusedWhileWaiting() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); put("upload.apk", a); watch.scanOnce(false); JSONObject selected = row(watch); arm(watch, selected);
        try { arm(watch, selected); fail("Must refuse simultaneous waits"); } catch (F1Watch.Refused expected) { assertEquals("replacement_already_armed", expected.code); }
    }
    @Test public void selectedWatcherRunsEvenWhenFullDeviceScanIsNotRunning() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); Files.delete(target.toPath()); arm(watch, row(watch));
        assertFalse(status(watch).getBoolean("watch_running")); assertTrue(status(watch).getBoolean("replacement_running"));
        Files.write(target.toPath(), new byte[]{1,2}); finished(watch, "succeeded"); assertArrayEquals(b, Files.readAllBytes(target.toPath()));
    }
    @Test public void sameSizeAndMtimeContentRewriteStillUpdatesDiscoveredCandidate() throws Exception {
        byte[] old = new byte[]{1,2,3}, next = new byte[]{4,5,6}; File target = put("upload.apk", old); long modified = target.lastModified();
        F1Watch watch = monitor(); watch.scanOnce(true); Files.write(target.toPath(), next); assertTrue(target.setLastModified(modified)); watch.scanOnce(false);
        assertEquals("ready", row(watch).getString("status")); assertEquals("rewritten", row(watch).getString("change"));
    }
    @Test public void incompleteBaselineRetainsCoverageLimit() throws Exception {
        F1Watch watch = monitor(config().put("roots", new JSONArray().put(temp.getRoot().getCanonicalPath()).put(new File(temp.getRoot(), "missing").getPath()))); watch.scanOnce(true);
        assertTrue(status(watch).getBoolean("baseline_complete")); assertFalse(status(watch).getBoolean("baseline_scope_complete")); assertFalse(status(watch).getBoolean("scan_complete"));
    }
    @Test public void nonApkFileNeverBecomesATarget() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); put("notes.txt", a); watch.scanOnce(false); assertEquals(0, status(watch).getJSONArray("candidates").length());
    }
    @Test public void wrongBHashFailsBeforeMonitoring() throws Exception {
        try { new F1Watch(config(), a, "test"); fail("Must refuse wrong B"); } catch (F1Watch.Refused expected) { assertEquals("replacement_identity_mismatch", expected.code); }
    }
    @Test public void onlyBIsBundledAndOldAOptionsAreRemoved() throws Exception {
        File root = new File(System.getProperty("actscope.assets"), "f1"); F1Fixtures fixtures = F1Fixtures.load(name -> {
            assertFalse("A must never be loaded", name.contains("-A.apk")); return new FileInputStream(new File(root, name));
        });
        assertFalse(new File(root, "actscope-f1-A.apk").exists()); assertFalse(fixtures.manifest.has("A")); assertTrue(fixtures.replacement.length > 0);
        JSONObject cfg = fixtures.configuration(new JSONObject().put("original_sha256", "obsolete").put("original_size_bytes", 1).put("replacement_path", "/unused").put("replacement_sha256", "wrong"));
        assertFalse(cfg.has("original_sha256")); assertFalse(cfg.has("original_size_bytes")); assertFalse(cfg.has("replacement_path"));
        assertEquals(fixtures.manifest.getJSONObject("B").getString("sha256"), cfg.getString("replacement_sha256")); assertEquals("manual", cfg.getString("replacement_mode"));
    }
    @Test public void obsoleteOriginalHashNeverFiltersDetectedPaths() throws Exception {
        F1Watch watch = monitor(config().put("original_sha256", "obsolete-not-a-hash").put("original_size_bytes", 999)); watch.scanOnce(true);
        File target = put("user.apk", new byte[]{8,9,10}); watch.scanOnce(false); Files.delete(target.toPath()); arm(watch, row(watch)); Files.write(target.toPath(), new byte[]{6});
        finished(watch, "succeeded"); assertArrayEquals(b, Files.readAllBytes(target.toPath()));
    }
    @Test public void rewritingAnAlreadyBFileDoesNotClaimContentChanged() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", b); watch.scanOnce(false); arm(watch, row(watch));
        Files.delete(target.toPath()); disappeared(watch); Files.write(target.toPath(), b); finished(watch, "succeeded");
        assertFalse(status(watch).getJSONObject("last_attempt").getBoolean("content_changed")); assertFalse(status(watch).getBoolean("observation_complete"));
    }
    @Test public void baselineCanBeDeclaredAfterDiscoveryBeforeNextWebInstallation() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); put("upload.apk", a); watch.scanOnce(false);
        assertFalse(status(watch).getBoolean("normal_baseline_verified"));
        watch.attempt(status(watch).getString("watch_id"), row(watch).getString("candidate_id"), true);
        assertTrue(status(watch).getBoolean("normal_baseline_verified")); assertEquals("operator_declaration", status(watch).getString("normal_baseline_source"));
    }
    @Test public void rearmingStartsFreshEvidenceAndKeepsPreviousAttemptInEvents() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File target = put("upload.apk", a); watch.scanOnce(false); Files.delete(target.toPath()); arm(watch, row(watch));
        Files.write(target.toPath(), a); finished(watch, "succeeded"); int events = status(watch).getJSONArray("events").length();
        arm(watch, row(watch)); JSONObject next = status(watch);
        assertFalse(next.getBoolean("replacement_attempted")); assertFalse(next.getBoolean("replacement_write_verified")); assertTrue(next.isNull("original_sha256"));
        assertFalse(next.has("last_attempt")); assertTrue(next.getJSONArray("events").length() > events);
    }
    @Test public void differentFilenameInSameDirectoryIsReplacedAndExistingApksAreUntouched() throws Exception {
        F1Watch watch = monitor(); watch.scanOnce(true); File source = put("xxx.apk", a); File existing = put("old.apk", new byte[]{1,2}); watch.scanOnce(false);
        JSONObject armed = arm(watch, row(watch));
        assertEquals(temp.getRoot().getCanonicalPath(), armed.getJSONObject("pending_replacement").getString("directory"));
        assertEquals(source.getCanonicalPath(), armed.getJSONObject("pending_replacement").getString("source_apk_path"));
        File next = put("yyy.apk", new byte[]{9,8,7}); finished(watch, "succeeded"); JSONObject action = status(watch).getJSONObject("last_attempt");
        assertArrayEquals(b, Files.readAllBytes(next.toPath())); assertArrayEquals(a, Files.readAllBytes(source.toPath())); assertArrayEquals(new byte[]{1,2}, Files.readAllBytes(existing.toPath()));
        assertEquals(next.getCanonicalPath(), action.getString("path")); assertEquals("new_apk_in_directory", action.getString("trigger"));
    }
    @Test public void nestedAndSiblingApksAndNonApkFilesAreNotReplaced() throws Exception {
        File directory = temp.newFolder("uploads"), sibling = temp.newFolder("other");
        F1Watch watch = monitor(); watch.scanOnce(true); File source = new File(directory, "xxx.apk"); Files.write(source.toPath(), a); watch.scanOnce(false); arm(watch, row(watch));
        File nested = new File(new File(directory, "sub"), "nested.apk"); assertTrue(nested.getParentFile().mkdir()); Files.write(nested.toPath(), a);
        File outside = new File(sibling, "outside.apk"); Files.write(outside.toPath(), a); File notes = new File(directory, "notes.txt"); Files.write(notes.toPath(), a);
        Thread.sleep(100); assertFalse(status(watch).getBoolean("replacement_attempted"));
        File next = new File(directory, "different.APK"); Files.write(next.toPath(), a); finished(watch, "succeeded"); assertArrayEquals(b, Files.readAllBytes(next.toPath()));
        for (File unchanged : new File[]{nested, outside, notes, source}) assertArrayEquals(a, Files.readAllBytes(unchanged.toPath()));
    }
    @Test public void parentDirectoryRedirectionIsRefused() throws Exception {
        File directory = temp.newFolder("uploads"), outside = temp.newFolder("other");
        F1Watch watch = monitor(); watch.scanOnce(true); File source = new File(directory, "xxx.apk"); Files.write(source.toPath(), a); watch.scanOnce(false); arm(watch, row(watch));
        File victim = new File(outside, "yyy.apk"); Files.write(victim.toPath(), a);
        Files.move(directory.toPath(), new File(temp.getRoot(), "saved").toPath()); Files.createSymbolicLink(directory.toPath(), outside.toPath()); finished(watch, "failed");
        assertArrayEquals(a, Files.readAllBytes(victim.toPath())); assertFalse(status(watch).getBoolean("replacement_attempted"));
    }
    @Test public void missingParentCanBeRecreatedWithADifferentApkName() throws Exception {
        File directory = temp.newFolder("uploads"); F1Watch watch = monitor(); watch.scanOnce(true);
        File source = new File(directory, "xxx.apk"); Files.write(source.toPath(), a); watch.scanOnce(false); Files.delete(source.toPath()); Files.delete(directory.toPath());
        JSONObject waiting = arm(watch, row(watch)); assertFalse(waiting.getJSONObject("pending_replacement").getBoolean("initial_directory_present"));
        assertTrue(directory.mkdir()); File next = new File(directory, "random-123.apk"); Files.write(next.toPath(), a); finished(watch, "succeeded");
        assertArrayEquals(b, Files.readAllBytes(next.toPath())); assertFalse(source.exists());
    }
    @Test public void excessiveDirectoryEntriesRefuseArmingInsteadOfClaimingCoverage() throws Exception {
        F1Watch watch = monitor(config().put("max_scan_entries", 10)); watch.scanOnce(true); put("xxx.apk", a); watch.scanOnce(false);
        for (int i = 0; i < 12; i++) put("extra-" + i + ".txt", a);
        try { arm(watch, row(watch)); fail("Incomplete directory baseline must be refused"); }
        catch (F1Watch.Refused expected) { assertEquals("directory_entry_limit_reached", expected.code); }
        assertFalse(status(watch).getBoolean("replacement_running")); assertFalse(status(watch).getBoolean("replacement_attempted"));
    }
}
