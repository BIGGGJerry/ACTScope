package tv.danmaku.bili;

import org.json.*;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;

/** Discover APK paths, then explicitly watch the selected parent for the next uploaded APK. */
final class F1Watch {
    static final class Refused extends IOException {
        final String code;
        Refused(String code) { super(code); this.code = code; }
    }
    private final List<File> roots, exclusions = new ArrayList<>();
    private final byte[] replacement;
    private final String replacementHash;
    private final int poll, seconds, maxEntries, scanTimeoutMs;
    private final JSONObject result;
    private final JSONArray events = new JSONArray();
    private final LinkedHashMap<String, JSONObject> candidates = new LinkedHashMap<>();
    private Map<String, String> previous = new HashMap<>();
    private int droppedEvents, droppedCandidates;
    private volatile boolean running;
    private volatile boolean replacementRunning;
    private boolean allScansComplete = true;
    private Thread thread, replacementThread;
    private final int replacementPollMs, replacementSeconds;

    F1Watch(JSONObject config, byte[] replacement, String identity) throws Exception {
        if (replacement == null || replacement.length < 1 || replacement.length > 32 * 1024 * 1024) throw new Refused("invalid_replacement");
        this.replacement = replacement.clone();
        replacementHash = FileProbe.requireHash(config.getString("replacement_sha256"));
        if (!replacementHash.equals(FileProbe.digest(new ByteArrayInputStream(this.replacement)))) throw new Refused("replacement_identity_mismatch");
        roots = FileProbe.roots(config);
        for (String path : new String[]{"/proc", "/sys", "/dev"}) exclusions.add(new File(path).getCanonicalFile());
        if (config.has("replacement_path")) exclusions.add(new File(config.getString("replacement_path")).getCanonicalFile());
        poll = Math.min(30000, Math.max(250, config.optInt("poll_ms", 1000)));
        seconds = Math.min(3600, Math.max(1, config.optInt("window_seconds", 300)));
        maxEntries = Math.min(50000, Math.max(10, config.optInt("max_scan_entries", 50000)));
        scanTimeoutMs = Math.min(30000, Math.max(1, config.optInt("scan_timeout_ms", 10000)));
        replacementPollMs = Math.min(5000, Math.max(10, config.optInt("replacement_poll_ms", 50)));
        replacementSeconds = Math.min(3600, Math.max(1, config.optInt("replacement_window_seconds", 300)));
        JSONArray excluded = new JSONArray(); for (File file : exclusions) excluded.put(file.getPath());
        result = new JSONObject().put("schema", "actscope.device.f1.v1").put("failure", "F1")
            .put("watch_id", UUID.randomUUID().toString()).put("replacement_mode", "manual")
            .put("replacement_trigger", "next_apk_in_selected_directory")
            .put("run_id", config.optString("run_id", "")).put("instance_id", config.optString("instance_id", "")).put("build_id", config.optString("build_id", ""))
            .put("execution_identity", identity).put("original_sha256", JSONObject.NULL).put("replacement_sha256", replacementHash)
            .put("target_selection", "detected_apk_parent_directory").put("original_identity_source", "not_observed")
            .put("roots", config.getJSONArray("roots")).put("excluded_roots", excluded).put("fixture_package", config.optString("fixture_package", ""))
            .put("poll_ms", poll).put("window_seconds", seconds).put("scan_timeout_ms", scanTimeoutMs).put("max_scan_entries", maxEntries)
            .put("replacement_poll_ms", replacementPollMs).put("replacement_window_seconds", replacementSeconds)
            .put("replacement_state", "idle")
            .put("replacement_attempted", false).put("replacement_write_verified", false)
            .put("normal_baseline_verified", config.optBoolean("normal_baseline_verified", false))
            .put("normal_baseline_source", config.optBoolean("normal_baseline_verified", false) ? "operator_declaration" : "not_recorded")
            .put("original_install_task_id", JSONObject.NULL).put("observed_install_task_id", JSONObject.NULL)
            .put("install_completed", false).put("installed_identity_verified", false).put("legitimate_transform_excluded", false)
            .put("observation_complete", false).put("scan_complete", false).put("baseline_complete", false)
            .put("phase", "idle").put("started_at", System.currentTimeMillis());
    }
    synchronized boolean isRunning() { return running || replacementRunning; }
    synchronized void start() throws Exception {
        if (running) throw new Refused("watch_already_running");
        running = true; result.put("phase", "baseline_scan");
        thread = new Thread(this::run, "actscope-f1-scan-only"); thread.start();
    }
    synchronized void stop() throws Exception {
        if (running) { result.put("stopped_reason", "stopped_by_user"); thread.interrupt(); }
        if (replacementRunning) replacementThread.interrupt();
    }
    private void run() {
        try {
            scanOnce(true);
            long deadline = System.nanoTime() + seconds * 1000000000L;
            synchronized (this) { result.put("monitoring_until_device", System.currentTimeMillis() + seconds * 1000L); }
            while (System.nanoTime() < deadline && !Thread.currentThread().isInterrupted()) {
                Thread.sleep(poll); scanOnce(false);
            }
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        catch (Exception e) { synchronized (this) { try { result.put("fatal_error", e.toString()).put("scan_complete", false); } catch (Exception ignored) {} } }
        finally { synchronized (this) {
            running = false;
            try { result.put("phase", "stopped").put("scan_in_progress", false).put("finished_at", System.currentTimeMillis()); }
            catch (Exception ignored) {}
        } }
    }
    void scanOnce(boolean baseline) throws Exception {
        synchronized (this) { result.put("scan_in_progress", true).put("scan_started_at_device", System.currentTimeMillis()); }
        Map<String, String> snapshot = new HashMap<>(); JSONArray errors = new JSONArray();
        long deadline = System.nanoTime() + scanTimeoutMs * 1000000L;
        FileProbe.walk(roots, maxEntries, errors, file -> {
            if (!file.getName().toLowerCase(Locale.ROOT).endsWith(".apk")) return;
            long size = file.length(), modified = file.lastModified(); String hash = "";
            // No preselected original identity: every detected APK can be selected.
            // A digest is evidence of the observed file, never an eligibility filter.
            try { hash = hashBefore(file, deadline); }
            catch (InterruptedException e) { throw e; }
            catch (IOException e) { FileProbe.error(errors, file.getPath(), "apk_hash_incomplete: " + e.getMessage()); }
            String fingerprint = size + ":" + modified + ":" + hash;
            String path = file.getCanonicalPath(); snapshot.put(path, fingerprint);
            if (baseline || fingerprint.equals(previous.get(path))) return;
            synchronized (this) {
                JSONObject old = candidates.get(path);
                if (old != null && "replaced".equals(old.optString("status")) && hash.equals(replacementHash)) return;
                JSONObject row = new JSONObject().put("candidate_id", UUID.randomUUID().toString()).put("path", path)
                    .put("change", previous.containsKey(path) ? "rewritten" : "new_to_observed_baseline")
                    .put("observed_at_device", System.currentTimeMillis()).put("size_bytes", size).put("last_modified_ms", modified)
                    .put("sha256", hash.isEmpty() ? JSONObject.NULL : hash).put("status", "ready");
                candidates.remove(path); candidates.put(path, row);
                if (candidates.size() > 40) { candidates.remove(candidates.keySet().iterator().next()); droppedCandidates++; }
                addEvent(new JSONObject(row.toString()).put("action", "candidate_detected"));
            }
        }, deadline, exclusions);
        synchronized (this) {
            if (errors.length() == 0) for (Map.Entry<String, JSONObject> entry : candidates.entrySet()) {
                if (!snapshot.containsKey(entry.getKey()) && "ready".equals(entry.getValue().optString("status"))) entry.getValue().put("status", "disappeared");
            }
            // An unreadable or bounded pass must not forget paths already observed.
            if (errors.length() == 0) previous = snapshot; else previous.putAll(snapshot);
            allScansComplete &= errors.length() == 0;
            result.put("scan_in_progress", false).put("last_scan_at_device", System.currentTimeMillis()).put("last_scan_apk_count", snapshot.size())
                .put("last_scan_error_count", errors.length()).put("scan_errors_may_be_truncated", errors.length() >= 512).put("scan_complete", allScansComplete);
            JSONArray saved = new JSONArray(); for (int i = 0; i < Math.min(errors.length(), 64); i++) saved.put(errors.get(i));
            result.put("last_scan_errors", saved).put("scan_errors_omitted", Math.max(0, errors.length() - saved.length()));
            if (baseline) {
                result.put("baseline_complete", true).put("baseline_scope_complete", errors.length() == 0).put("initial_apk_count", snapshot.size()).put("phase", "monitoring");
                addEvent(new JSONObject().put("baseline_complete", true).put("baseline_scope_complete", errors.length() == 0).put("initial_apk_count", snapshot.size()));
            }
        }
    }
    synchronized String attempt(String watchId, String candidateId) throws Exception {
        return attempt(watchId, candidateId, result.optBoolean("normal_baseline_verified"));
    }
    synchronized String attempt(String watchId, String candidateId, boolean normalBaselineVerified) throws Exception {
        if (!result.getString("watch_id").equals(watchId)) throw new Refused("watch_changed");
        if (replacementRunning) throw new Refused("replacement_already_armed");
        JSONObject row = null;
        for (JSONObject candidate : candidates.values()) if (candidateId.equals(candidate.optString("candidate_id"))) { row = candidate; break; }
        if (row == null) throw new Refused("candidate_changed");
        File sourceApk = new File(row.getString("path")), directory = sourceApk.getParentFile();
        if (directory == null) throw new Refused("invalid_target_directory");
        DirectorySnapshot initial = snapshotDirectory(directory, System.nanoTime() + scanTimeoutMs * 1000000L);
        String operation = UUID.randomUUID().toString();
        JSONObject waiting = new JSONObject().put("operation_id", operation).put("candidate_id", candidateId).put("path", sourceApk.getPath())
            .put("source_apk_path", sourceApk.getPath()).put("directory", directory.getPath()).put("recursive", false)
            .put("armed_at_device", System.currentTimeMillis()).put("expires_at_device", System.currentTimeMillis() + replacementSeconds * 1000L)
            .put("initial_target_present", initial.files.containsKey(sourceApk.getPath())).put("target_absent_observed", !initial.files.containsKey(sourceApk.getPath()))
            .put("initial_directory_present", initial.present).put("initial_apk_count", initial.files.size()).put("excluded_symlinks", initial.excludedLinks)
            .put("state", "waiting_for_next_upload");
        result.put("pending_replacement", waiting).put("replacement_state", "waiting_for_next_upload")
            .put("replacement_attempted", false).put("replacement_write_verified", false)
            .put("original_sha256", JSONObject.NULL).put("original_identity_source", "not_observed")
            .put("normal_baseline_verified", normalBaselineVerified).put("normal_baseline_source", normalBaselineVerified ? "operator_declaration" : "not_recorded");
        result.remove("last_attempt");
        addEvent(new JSONObject(waiting.toString()).put("action", "replacement_armed"));
        replacementRunning = true;
        replacementThread = new Thread(() -> awaitNextUpload(operation, directory, sourceApk.getPath(), initial.files), "actscope-f1-directory-watch");
        replacementThread.start(); return status();
    }
    private static final class DirectorySnapshot {
        final Map<String, String> files = new LinkedHashMap<>();
        boolean present;
        int excludedLinks;
    }
    private DirectorySnapshot snapshotDirectory(File directory, long deadline) throws Exception {
        if (Files.isSymbolicLink(directory.toPath()) || !directory.getPath().equals(directory.getCanonicalPath())) throw new Refused("directory_disappeared_or_redirected");
        DirectorySnapshot snapshot = new DirectorySnapshot();
        if (!directory.exists()) return snapshot;
        if (!directory.isDirectory()) throw new Refused("invalid_target_directory");
        File[] entries = directory.listFiles();
        if (entries == null) { if (!directory.exists()) return snapshot; throw new Refused("directory_unreadable"); }
        if (entries.length > maxEntries) throw new Refused("directory_entry_limit_reached");
        snapshot.present = true;
        Arrays.sort(entries, Comparator.comparing(File::getName));
        for (File entry : entries) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
            if (System.nanoTime() >= deadline) throw new Refused("directory_scan_timeout");
            if (!entry.getName().toLowerCase(Locale.ROOT).endsWith(".apk")) continue;
            if (Files.isSymbolicLink(entry.toPath())) { snapshot.excludedLinks++; continue; }
            if (!entry.isFile()) continue;
            String stamp = targetStamp(entry);
            if (stamp != null) snapshot.files.put(entry.getPath(), stamp);
        }
        return snapshot;
    }
    // Detect disappearance/reappearance, inode replacement, or an in-place size/mtime change.
    private static String targetStamp(File target) throws Exception {
        if (Files.isSymbolicLink(target.toPath()) || !target.getPath().equals(target.getCanonicalPath())) throw new Refused("target_disappeared_or_redirected");
        try {
            java.nio.file.attribute.BasicFileAttributes a = Files.readAttributes(target.toPath(), java.nio.file.attribute.BasicFileAttributes.class, java.nio.file.LinkOption.NOFOLLOW_LINKS);
            if (!a.isRegularFile()) throw new Refused("target_disappeared_or_redirected");
            return a.size() + ":" + a.lastModifiedTime() + ":" + a.fileKey();
        } catch (java.nio.file.NoSuchFileException e) { return null; }
    }
    private void awaitNextUpload(String operation, File directory, String sourceApkPath, Map<String, String> initialFiles) {
        long deadline = System.nanoTime() + replacementSeconds * 1000000000L;
        Map<String, String> previousFiles = initialFiles;
        Map<String, String> eligible = new LinkedHashMap<>(); String finish = "timed_out";
        try {
            watchDirectory:
            while (System.nanoTime() < deadline) {
                if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                DirectorySnapshot current = snapshotDirectory(directory, deadline);
                synchronized (this) {
                    JSONObject pending = result.getJSONObject("pending_replacement");
                    pending.put("last_scan_at_device", System.currentTimeMillis()).put("last_apk_count", current.files.size()).put("excluded_symlinks", current.excludedLinks);
                    if (!current.files.containsKey(sourceApkPath)) pending.put("target_absent_observed", true);
                    if (!current.present) pending.put("directory_absent_observed", true);
                }
                for (Map.Entry<String, String> entry : current.files.entrySet()) {
                    String old = previousFiles.get(entry.getKey());
                    if (!entry.getValue().equals(old)) eligible.put(entry.getKey(), old == null ? "new_apk_in_directory" : "rewritten_apk_in_directory");
                }
                eligible.keySet().retainAll(current.files.keySet());
                previousFiles = current.files;
                for (Map.Entry<String, String> entry : eligible.entrySet()) {
                    if (replaceFreshUpload(operation, new File(entry.getKey()), entry.getValue(), deadline)) { finish = "succeeded"; break watchDirectory; }
                }
                Thread.sleep(replacementPollMs);
            }
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); finish = "cancelled"; }
        catch (Exception e) {
            finish = "failed";
            synchronized (this) { try { result.getJSONObject("pending_replacement").put("reason", e instanceof Refused ? ((Refused)e).code : "target_watch_error").put("detail", e.toString()); } catch (Exception ignored) {} }
        } finally {
            synchronized (this) {
                replacementRunning = false;
                try {
                    JSONObject pending = result.getJSONObject("pending_replacement");
                    pending.put("state", finish).put("finished_at_device", System.currentTimeMillis()); result.put("replacement_state", finish);
                    addEvent(new JSONObject(pending.toString()).put("action", "replacement_watch_finished"));
                } catch (Exception ignored) {}
            }
        }
    }
    private boolean replaceFreshUpload(String operation, File target, String trigger, long deadline) throws Exception {
        JSONObject action = new JSONObject().put("action", "replacement_after_web_upload").put("operation_id", operation).put("path", target.getPath())
            .put("replacement_filename", target.getName()).put("replacement_name_policy", "preserve_detected_target_filename")
            .put("trigger", trigger).put("at_device", System.currentTimeMillis()).put("replacement_attempted", false).put("replacement_succeeded", false);
        boolean verified = false;
        try {
            String stamp = targetStamp(target); if (stamp == null) return false;
            String originalHash = hashBefore(target, deadline);
            if (!stamp.equals(targetStamp(target))) throw new Refused("target_changed");
            action.put("original_sha256", originalHash).put("original_identity_source", "fresh_target_before_write");
            synchronized (this) { result.put("original_sha256", originalHash).put("original_identity_source", "fresh_target_before_write").put("replacement_attempted", true); }
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
            action.put("replacement_attempted", true);
            boolean written = FileProbe.replaceOwned(target, originalHash, replacement);
            String post = hashBefore(target, deadline); verified = written && post.equals(replacementHash);
            action.put("replacement_succeeded", verified).put("post_write_sha256", post).put("write_returned", written)
                .put("content_changed", verified && !originalHash.equals(replacementHash))
                .put("reason", verified ? "replacement_verified_final_install_unchecked" : "replacement_not_verified");
        } catch (InterruptedException e) { throw e; }
        catch (Exception e) { action.put("reason", e instanceof Refused ? ((Refused)e).code : "replacement_io_error").put("detail", e.toString()); }
        synchronized (this) {
            result.put("last_attempt", action);
            if (verified) {
                result.put("replacement_write_verified", true);
                JSONObject row = candidates.get(target.getPath()); if (row != null) row.put("status", "replaced");
            }
            addEvent(action);
        }
        return verified;
    }
    private static String hashBefore(File file, long deadline) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); byte[] bytes = new byte[65536]; int n;
        try (InputStream in = new FileInputStream(file)) {
            while ((n = in.read(bytes)) != -1) {
                if (Thread.currentThread().isInterrupted()) throw new InterruptedException("APK hash interrupted");
                if (System.nanoTime() >= deadline) throw new IOException("APK hash time limit reached");
                digest.update(bytes, 0, n);
            }
        }
        return FileProbe.hex(digest.digest());
    }
    private void addEvent(JSONObject event) throws Exception {
        event.put("recorded_at_device", System.currentTimeMillis());
        if (events.length() >= 200) { events.remove(0); droppedEvents++; } events.put(event);
    }
    synchronized String status() throws Exception {
        JSONObject snapshot = new JSONObject(result.toString()); JSONArray rows = new JSONArray(), log = new JSONArray(events.toString());
        List<JSONObject> list = new ArrayList<>(candidates.values()); Collections.reverse(list); for (JSONObject row : list) rows.put(new JSONObject(row.toString()));
        snapshot.put("watch_running", running).put("replacement_running", replacementRunning).put("candidates", rows).put("events", log).put("candidate_entries_dropped", droppedCandidates).put("events_dropped", droppedEvents);
        int omitted = 0;
        while (snapshot.toString().length() > 220000 && log.length() > 0) { log.remove(0); omitted++; }
        snapshot.put("events_omitted_from_status", omitted); omitted = 0;
        JSONArray errors = snapshot.optJSONArray("last_scan_errors");
        while (snapshot.toString().length() > 220000 && errors != null && errors.length() > 0) { errors.remove(errors.length() - 1); omitted++; }
        snapshot.put("scan_errors_omitted_from_status", omitted); omitted = 0;
        while (snapshot.toString().length() > 220000 && rows.length() > 0) { rows.remove(rows.length() - 1); omitted++; }
        snapshot.put("candidate_entries_omitted_from_status", omitted);
        return snapshot.toString();
    }
}
