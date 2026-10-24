package tv.danmaku.bili;

import org.json.*;
import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;

/** Identical traversal/metadata code in ordinary-app and Shizuku process contexts. */
final class FileProbe {
    interface Visitor { void visit(File file) throws Exception; }
    static String sha256(File file) throws Exception { try (InputStream in = new FileInputStream(file)) { return digest(in); } }
    static String digest(InputStream in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256"); byte[] b = new byte[65536]; int n;
        while ((n = in.read(b)) != -1) md.update(b, 0, n);
        return hex(md.digest());
    }
    static String hex(byte[] bytes) { StringBuilder s = new StringBuilder(); for (byte b : bytes) s.append(String.format(Locale.ROOT, "%02x", b & 255)); return s.toString(); }
    static String requireHash(String hash) { if (!hash.matches("[a-fA-F0-9]{64}")) throw new IllegalArgumentException("Expected SHA-256 must contain 64 hex characters"); return hash.toLowerCase(Locale.ROOT); }
    static List<File> roots(JSONObject cfg) throws Exception { return roots(cfg, 16); }
    private static List<File> roots(JSONObject cfg, int maximum) throws Exception {
        JSONArray roots = cfg.getJSONArray("roots"); if (roots.length() < 1 || roots.length() > maximum) throw new IllegalArgumentException("Specify 1–" + maximum + " explicit roots");
        List<File> out = new ArrayList<>();
        for (int i = 0; i < roots.length(); i++) { File f = new File(roots.getString(i)); if (!f.isAbsolute()) throw new IllegalArgumentException("Roots must be absolute"); out.add(f.getCanonicalFile()); }
        return out;
    }
    static void walk(List<File> roots, int maxEntries, JSONArray errors, Visitor visitor) throws Exception {
        walk(roots, maxEntries, errors, visitor, Long.MAX_VALUE);
    }
    static void walk(List<File> roots, int maxEntries, JSONArray errors, Visitor visitor, long deadlineNanos) throws Exception {
        walk(roots, maxEntries, errors, visitor, deadlineNanos, Collections.emptyList());
    }
    static void walk(List<File> roots, int maxEntries, JSONArray errors, Visitor visitor, long deadlineNanos, List<File> exclusions) throws Exception {
        Set<String> seen = new HashSet<>(); ArrayDeque<File> todo = new ArrayDeque<>(roots); int count = 0;
        while (!todo.isEmpty()) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException("Scan interrupted");
            File f = todo.pop();
            if (System.nanoTime() >= deadlineNanos) { error(errors, f.getAbsolutePath(), "scan_timeout_reached"); return; }
            if (Files.isSymbolicLink(f.toPath())) continue;
            String path = f.getAbsolutePath(); if (!seen.add(path)) continue;
            boolean excluded = false;
            for (File exclusion : exclusions) if (path.equals(exclusion.getPath()) || path.startsWith(exclusion.getPath() + File.separator)) { excluded = true; break; }
            if (excluded) continue;
            if (++count > maxEntries) { error(errors, path, "entry_limit_reached"); return; }
            if (!f.exists()) { error(errors, path, "missing_or_inaccessible"); continue; }
            if (!f.canRead()) { error(errors, path, "read_permission_denied"); continue; }
            if (f.isDirectory()) {
                File[] children = f.listFiles();
                if (children == null) { error(errors, path, "list_failed"); continue; }
                Arrays.sort(children, Comparator.comparing(File::getName));
                for (File child : children) todo.add(child);
            } else if (f.isFile()) {
                try { visitor.visit(f); } catch (InterruptedException e) { throw e; }
                catch (Exception e) { error(errors, path, e.getClass().getSimpleName() + ": " + e.getMessage()); }
            }
        }
    }
    static void error(JSONArray errors, String path, String reason) throws Exception {
        if (errors.length() < 512) errors.put(new JSONObject().put("path", path).put("reason", reason));
    }
    private static List<JSONObject> rules(JSONObject cfg, List<File> scanRoots) throws Exception {
        List<JSONObject> out = new ArrayList<>();
        JSONArray manifest = cfg.optJSONArray("rule_manifest");
        if (manifest == null) return out;
        if (manifest.length() < 1 || manifest.length() > 512) throw new IllegalArgumentException("rule_manifest must contain 1–512 exact rules");
        Set<String> allowed = new HashSet<>();
        for (int i = 0; i < manifest.length(); i++) {
            JSONObject rule = new JSONObject(manifest.getJSONObject(i).toString());
            File path = new File(rule.getString("path"));
            if (!path.isAbsolute()) throw new IllegalArgumentException("Rule paths must be absolute");
            String kind = rule.getString("kind");
            if (!"file".equals(kind) && !"directory".equals(kind)) throw new IllegalArgumentException("Rule kind must be file/directory");
            rule.getString("app"); rule.getString("source");
            if (rule.getInt("line") < 1) throw new IllegalArgumentException("Rule source line must be positive");
            rule.put("canonical_path", path.getCanonicalPath()); allowed.add(path.getCanonicalPath()); out.add(rule);
        }
        for (File root : scanRoots) if (!allowed.contains(root.getCanonicalPath())) throw new IllegalArgumentException("Every scan root must be an exact rule_manifest path");
        Set<String> selected = new HashSet<>(); for (File root : scanRoots) selected.add(root.getCanonicalPath());
        if (!selected.equals(allowed)) throw new IllegalArgumentException("roots must cover every rule_manifest path");
        out.sort((a, b) -> Integer.compare(b.optString("canonical_path").length(), a.optString("canonical_path").length()));
        return out;
    }
    private static void associate(JSONObject row, List<JSONObject> rules) throws Exception {
        String path = new File(row.getString("path")).getCanonicalPath(); JSONArray matches = new JSONArray();
        for (JSONObject rule : rules) {
            String base = rule.getString("canonical_path");
            if (path.equals(base) || ("directory".equals(rule.getString("kind")) && path.startsWith(base.equals("/") ? "/" : base + "/"))) {
                if (matches.length() >= 16) { row.put("rule_matches_truncated", true); continue; }
                JSONObject copy = new JSONObject(rule.toString()); copy.remove("canonical_path"); matches.put(copy);
            }
        }
        if (matches.length() > 0) {
            JSONObject first = matches.getJSONObject(0);
            row.put("rule_source", first.getString("source")).put("rule_line", first.getInt("line"))
                .put("app", first.getString("app")).put("rule_path", first.getString("path"))
                .put("rule_kind", first.getString("kind"));
            if (matches.length() > 1) row.put("rule_matches", matches);
        }
    }
    static JSONObject scan(JSONObject cfg, String identity) throws Exception {
        long timeoutMs = Math.min(120000, Math.max(1, cfg.optLong("scan_timeout_ms", 30000)));
        long deadlineNanos = System.nanoTime() + timeoutMs * 1000000L;
        JSONArray files = new JSONArray(), errors = new JSONArray();
        int limit = Math.min(50000, Math.max(1, cfg.optInt("max_scan_entries", 10000)));
        int maxResults = Math.min(500, Math.max(1, cfg.optInt("max_results", 200)));
        List<File> roots = roots(cfg, 512);
        List<JSONObject> manifest = rules(cfg, roots);
        JSONArray ruleObservations = new JSONArray();
        Set<String> blockedRoots = new HashSet<>();
        for (JSONObject rule : manifest) {
            File root = new File(rule.getString("canonical_path"));
            String actual = !root.exists() ? "missing_or_inaccessible" : !root.canRead() ? "permission_denied" : root.isDirectory() ? "directory" : root.isFile() ? "file" : "other";
            JSONObject observation = new JSONObject().put("path", root.getPath()).put("observed_kind", actual);
            observation.put("rule_source", rule.getString("source")).put("rule_line", rule.getInt("line"))
                .put("app", rule.getString("app")).put("rule_path", rule.getString("path")).put("rule_kind", rule.getString("kind"));
            ruleObservations.put(observation);
            if (("file".equals(actual) || "directory".equals(actual)) && !actual.equals(rule.getString("kind"))) {
                error(errors, root.getPath(), "rule_kind_mismatch: expected " + rule.getString("kind") + ", observed " + actual);
                blockedRoots.add(root.getPath());
            }
        }
        List<File> traversableRoots = new ArrayList<>();
        for (File root : roots) if (!blockedRoots.contains(root.getPath())) traversableRoots.add(root);
        JSONObject out = new JSONObject().put("schema", "actscope.device.f6.v1").put("failure", "F6")
            .put("run_id", cfg.optString("run_id", "")).put("instance_id", cfg.optString("instance_id", "")).put("build_id", cfg.optString("build_id", ""))
            .put("execution_identity", identity).put("scan_started_at", System.currentTimeMillis())
            .put("roots", cfg.getJSONArray("roots")).put("files", files).put("access_errors", errors)
            .put("rule_manifest", cfg.optJSONArray("rule_manifest") == null ? new JSONArray() : cfg.getJSONArray("rule_manifest"))
            .put("rule_observations", ruleObservations)
            .put("ui", new JSONArray()).put("ui_scan_complete", false);
        final boolean[] truncated = {false};
        walk(traversableRoots, limit, errors, f -> {
            String suffix = cfg.optString("suffix", ""); if (!suffix.isEmpty() && !f.getName().endsWith(suffix)) return;
            if (files.length() >= maxResults) { truncated[0] = true; return; }
            // Attribution is never inferred from directory names. A researcher must review records.
            JSONObject row = new JSONObject().put("path", f.getAbsolutePath()).put("kind", "file").put("exists", true)
                .put("readable", f.canRead()).put("size", f.length()).put("modified_at", f.lastModified())
                .put("expected_cleanup", false).put("attributed_to_prior_session", false)
                .put("provenance_evidence", "").put("public_resource", JSONObject.NULL);
            if (cfg.optBoolean("hash_files", false)) row.put("sha256", sha256(f));
            associate(row, manifest); files.put(row);
        }, deadlineNanos);
        for (int i = 0; i < errors.length(); i++) associate(errors.getJSONObject(i), manifest);
        while (files.toString().length() > 220000) { files.remove(files.length() - 1); truncated[0] = true; }
        int errorsDropped = 0, ruleObservationsDropped = 0;
        while (out.toString().length() > 240000) {
            truncated[0] = true;
            if (files.length() > 0) files.remove(files.length() - 1);
            else if (ruleObservations.length() > 0) { ruleObservations.remove(ruleObservations.length() - 1); ruleObservationsDropped++; }
            else if (errors.length() > 0) { errors.remove(errors.length() - 1); errorsDropped++; }
            else throw new IllegalArgumentException("Rule manifest is too large for Binder evidence export; split the rule set");
        }
        out.put("file_scan_complete", errors.length() == 0 && !truncated[0]).put("results_truncated", truncated[0])
            .put("errors_dropped", errorsDropped).put("rule_observations_dropped", ruleObservationsDropped)
            .put("scan_timeout_ms", timeoutMs)
            .put("scan_finished_at", System.currentTimeMillis());
        return out;
    }
    static byte[] controlledReplacement(File f, String expected) throws Exception {
        if (!f.isFile() || f.length() > 32 * 1024 * 1024 || f.length() < 1) throw new IllegalArgumentException("Replacement must be a 1B–32MiB test APK");
        byte[] bytes = Files.readAllBytes(f.toPath());
        if (!hex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(requireHash(expected))) throw new IllegalArgumentException("Replacement SHA-256 mismatch");
        return bytes;
    }
    static boolean replaceOwned(File f, String original, byte[] replacement) throws Exception {
        if (Files.isSymbolicLink(f.toPath())) return false;
        try (RandomAccessFile file = new RandomAccessFile(f, "rw"); FileChannel channel = file.getChannel(); FileLock ignored = channel.tryLock()) {
            if (ignored == null) return false;
            // Compare the open target with the identity captured for this explicit action.
            MessageDigest md = MessageDigest.getInstance("SHA-256"); byte[] b = new byte[65536]; int n;
            while ((n = file.read(b)) != -1) md.update(b, 0, n);
            if (!hex(md.digest()).equals(original)) return false;
            file.seek(0); file.write(replacement); file.setLength(replacement.length); file.getFD().sync();
            return true;
        }
    }
}
