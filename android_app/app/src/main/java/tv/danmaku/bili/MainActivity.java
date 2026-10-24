package tv.danmaku.bili;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.PixelFormat;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.*;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.*;
import org.json.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import rikka.shizuku.Shizuku;

public class MainActivity extends Activity {
    private LinearLayout layout;
    private EditText endpoint, run, token, period, watchConfig, scanConfig, flowConfig;
    private TextView state, f6Status, shizukuStatus, exportStatus;
    private TextView overlayStatus;
    private CheckBox overlayEnabled;
    private FloatingOverlay floatingOverlay;
    private Spinner f6Channel;
    private ProgressBar f6Progress;
    private Button f6Start, f6Resume, exportButton;
    private boolean exporting;
    private TextView f1Status, f1Path;
    private Spinner f1Candidates;
    private Button f1Start, f1Attempt;
    private CheckBox f1Baseline;
    private final List<JSONObject> f1Rows = new ArrayList<>();
    private JSONObject f1Evidence = new JSONObject();
    private String selectedCandidateId = "", displayedCandidates = "";
    private String f1OperationError = "";
    private volatile boolean f1Busy;
    private boolean serviceHasF1Watch;
    private volatile int f1Generation;
    private volatile boolean f6Scanning, destroyed;
    private long scanStarted;
    private JSONObject pendingF6Context;
    private volatile IUserService shell;
    private boolean bound;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    // F1 Binder polling cannot hold up an F6 scan or the main-thread progress display.
    private final ExecutorService statusExecutor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean statusPolling = new AtomicBoolean();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Shizuku.UserServiceArgs serviceArgs = new Shizuku.UserServiceArgs(new ComponentName(BuildConfig.APPLICATION_ID, UserService.class.getName()))
        .daemon(false).processNameSuffix("probe_shell").debuggable(BuildConfig.DEBUG).version(BuildConfig.PROBE_BUILD_ID.hashCode() & 0x7fffffff);
    private final Runnable connectionTimeout = () -> {
        if (destroyed || shellConnected()) return;
        unbindShell();
        shizukuStatus.setText(R.string.shizuku_bind_timeout);
        if (pendingF6Context != null) {
            pendingF6Context = null;
            f6Error(new IllegalStateException(getString(R.string.shizuku_bind_timeout)));
        }
    };
    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            if (destroyed) return;
            shell = IUserService.Stub.asInterface(binder);
            serviceHasF1Watch = false; f1Generation++;
            handler.removeCallbacks(connectionTimeout);
            if (!shellConnected()) { connectionLost(); return; }
            shizukuStatus.setText(R.string.shizuku_connected);
            if (pendingF6Context != null) {
                JSONObject context = pendingF6Context; pendingF6Context = null;
                try { startFileScan(context, true); } catch (Exception e) { f6Error(e); }
            }
        }
        @Override public void onServiceDisconnected(ComponentName name) { connectionLost(); }
        @Override public void onBindingDied(ComponentName name) { connectionLost(); }
        @Override public void onNullBinding(ComponentName name) { connectionLost(); }
    };
    private final Shizuku.OnRequestPermissionResultListener permissionListener = (code, granted) -> {
        if (code != 1001 || destroyed) return;
        if (granted == PackageManager.PERMISSION_GRANTED) bindShell();
        else { shizukuStatus.setText(R.string.shizuku_denied); showError(new IllegalStateException(getString(R.string.shizuku_denied))); }
    };
    private final Shizuku.OnBinderReceivedListener binderReceived = this::autoConnectShell;
    private final Shizuku.OnBinderDeadListener binderDead = this::connectionLost;
    private final Runnable pollWatch = new Runnable() {
        @Override public void run() {
            if (destroyed) return;
            refreshF6();
            updateF1Selection();
            if (!f1Busy && shellConnected() && statusPolling.compareAndSet(false, true)) {
                final IUserService connected = shell;
                final int generation = f1Generation;
                statusExecutor.execute(() -> {
                    try { recordF1Result(connected.status(), generation); }
                    catch (Exception ignored) { }
                    finally { statusPolling.set(false); }
                });
            }
            handler.postDelayed(this, 1000);
        }
    };

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        floatingOverlay = new FloatingOverlay(this);
        ScrollView scroll = new ScrollView(this);
        layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(24, 28, 24, 24);
        scroll.addView(layout); setContentView(scroll);
        label(R.string.probe_title);
        label(getString(R.string.probe_intro, ProbeConfig.instance(this), BuildConfig.PROBE_BUILD_ID));
        JSONObject cfg; try { cfg = ProbeConfig.read(this); } catch (Exception e) { cfg = new JSONObject(); }
        endpoint = field(R.string.backend_label, cfg.optString("endpoint", ""), false);
        String experiment = ProbeConfig.prefs(this).getString("experiment_run_id", cfg.optString("run_id", ""));
        if (experiment.isEmpty()) { experiment = ExperimentIds.local(); ProbeConfig.prefs(this).edit().putString("experiment_run_id", experiment).apply(); }
        run = field(R.string.run_label, experiment, false); label(R.string.run_help);
        token = field(R.string.run_token, cfg.optString("token", ""), false);
        token.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        period = field(R.string.heartbeat_period, "" + ProbeConfig.prefs(this).getInt("period_minutes", 15), false);
        button(R.string.start_sampling, () -> {
            int minutes; try { minutes = Integer.parseInt(text(period)); } catch (NumberFormatException e) { throw new IllegalArgumentException(getString(R.string.period_invalid)); }
            if (minutes < 15) throw new IllegalArgumentException(getString(R.string.period_invalid));
            ProbeConfig.save(this, text(endpoint), text(run), text(token)); Telemetry.start(this, minutes); refresh();
        });
        button(R.string.sample_now, () -> { Telemetry.immediate(this); message(getString(R.string.sample_queued)); });
        button(R.string.stop_sampling, () -> { Telemetry.stop(this); refresh(); });
        button(R.string.retry_uploads, () -> { Telemetry.upload(this); message(getString(R.string.upload_queued)); });
        button(R.string.open_accessibility, this::openAccessibility);
        label(R.string.overlay_section);
        overlayEnabled = new CheckBox(this);
        overlayEnabled.setText(R.string.overlay_enabled);
        overlayEnabled.setChecked(ProbeConfig.prefs(this).getBoolean("overlay_enabled", true));
        layout.addView(overlayEnabled);
        overlayStatus = label("");
        button(R.string.overlay_open_settings, this::openOverlaySettings);
        overlayEnabled.setOnCheckedChangeListener((button, enabled) -> {
            ProbeConfig.prefs(this).edit().putBoolean("overlay_enabled", enabled).apply();
            if (enabled) {
                if (Settings.canDrawOverlays(this)) applyFloatingOverlay();
                else openOverlaySettings();
            } else {
                floatingOverlay.hide();
                updateOverlayStatus();
            }
        });
        label(R.string.permission_state_privacy);
        button(R.string.request_device_admin, () -> {
            Intent intent = new Intent(android.app.admin.DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
                .putExtra(android.app.admin.DevicePolicyManager.EXTRA_DEVICE_ADMIN, ProbePermissions.deviceAdminComponent(this))
                .putExtra(android.app.admin.DevicePolicyManager.EXTRA_ADD_EXPLANATION, getString(R.string.device_admin_explanation));
            startActivity(intent);
        });
        button(R.string.open_notification_listener_settings, () -> {
            Intent intent = new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
            if (intent.resolveActivity(getPackageManager()) == null) throw new IllegalStateException(getString(R.string.notification_listener_settings_unavailable));
            startActivity(intent);
        });
        state = label(""); button(R.string.refresh_status, this::refresh);
        label(R.string.shizuku_intro);
        shizukuStatus = label(R.string.shizuku_not_running);
        button(R.string.connect_shizuku, () -> {
            if (!Shizuku.pingBinder()) throw new IllegalStateException(getString(R.string.shizuku_start_first));
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                if (shellConnected()) shizukuStatus.setText(R.string.shizuku_connected);
                else { unbindShell(); bindShell(); }
            } else Shizuku.requestPermission(1001);
        });
        label(R.string.f1_intro);
        label(R.string.f1_fixture_hint);
        f1Baseline = new CheckBox(this); f1Baseline.setText(R.string.f1_baseline_confirmed); layout.addView(f1Baseline);
        f1Start = button(R.string.f1_start, this::startF1Watch);
        f1Status = label(R.string.f1_idle);
        label(R.string.f1_choose_path);
        f1Candidates = new Spinner(this, Spinner.MODE_DROPDOWN);
        f1Candidates.setDropDownWidth(LinearLayout.LayoutParams.MATCH_PARENT);
        layout.addView(f1Candidates, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        f1Candidates.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                selectedCandidateId = position < f1Rows.size() ? f1Rows.get(position).optString("candidate_id") : ""; updateF1Selection();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { selectedCandidateId = ""; updateF1Selection(); }
        });
        f1Path = label(R.string.f1_no_candidates); f1Path.setTextIsSelectable(true);
        f1Path.setSingleLine(false); f1Path.setMaxLines(Integer.MAX_VALUE); f1Path.setEllipsize(null); f1Path.setHorizontallyScrolling(false);
        f1Path.setTextDirection(View.TEXT_DIRECTION_LTR);
        button(R.string.f1_copy_path, () -> {
            JSONObject row = selectedF1Candidate(); if (row == null) throw new IllegalStateException(getString(R.string.f1_no_candidates));
            ((ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("F1 APK path", row.optString("path")));
            Toast.makeText(this, R.string.f1_copied_path, Toast.LENGTH_SHORT).show();
        });
        f1Attempt = button(R.string.f1_attempt, this::attemptF1Hijack);
        button(R.string.f1_stop, () -> {
            IUserService connected = requireShell(); runF1Action(generation -> recordF1Result(connected.stopWatch(), generation));
        });
        LinearLayout f1MainLayout = layout;
        LinearLayout f1Advanced = new LinearLayout(this); f1Advanced.setOrientation(LinearLayout.VERTICAL); f1Advanced.setVisibility(View.GONE);
        button(R.string.f1_advanced_toggle, () -> f1Advanced.setVisibility(f1Advanced.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE));
        layout.addView(f1Advanced); layout = f1Advanced; label(R.string.f1_advanced_intro);
        watchConfig = field(R.string.f1_config, ProbeConfig.prefs(this).getString("f1_manual_options", "{\"roots\":[\"/data/local/tmp\",\"/sdcard\",\"/data/app\",\"/\"],\"window_seconds\":300,\"poll_ms\":1000,\"max_scan_entries\":50000,\"scan_timeout_ms\":10000}"), true);
        button(R.string.f1_fetch, () -> { IUserService connected = requireShell(); background(() -> recordF1Result(connected.status(), f1Generation)); });
        layout = f1MainLayout;
        try { refreshF1(new JSONObject(ProbeConfig.prefs(this).getString("f1_result", "{}"))); }
        catch (Exception e) { refreshF1(new JSONObject()); }
        label(R.string.f6_intro);
        f6Status = label(UiStatus.f6(this));
        f6Progress = new ProgressBar(this); f6Progress.setVisibility(View.GONE); layout.addView(f6Progress);
        f6Channel = new Spinner(this);
        f6Channel.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item,
            new String[]{getString(R.string.f6_channel_auto), getString(R.string.f6_channel_app), getString(R.string.f6_channel_shizuku)}));
        layout.addView(f6Channel);
        f6Start = button(R.string.f6_start, this::startBuiltinF6, true);
        f6Resume = button(R.string.f6_resume, this::resumeBuiltinF6, true);
        button(R.string.f6_stop, () -> { if (ProbeAccessibilityService.active != null) ProbeAccessibilityService.active.stopFlow(); refreshF6(); });
        button(R.string.shared_file_access, () -> {
            if (Build.VERSION.SDK_INT >= 30) startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + getPackageName())));
            else requestPermissions(new String[]{android.Manifest.permission.READ_EXTERNAL_STORAGE}, 2001);
        });
        LinearLayout mainLayout = layout;
        LinearLayout advanced = new LinearLayout(this); advanced.setOrientation(LinearLayout.VERTICAL); advanced.setVisibility(View.GONE);
        button(R.string.f6_advanced_toggle, () -> advanced.setVisibility(advanced.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE));
        layout.addView(advanced); layout = advanced;
        label(R.string.f6_advanced_intro);
        scanConfig = field(R.string.f6_config, ProbeConfig.prefs(this).getString("scan_config", "{\"roots\":[\"/sdcard/Download\"],\"max_scan_entries\":10000,\"max_results\":200,\"hash_files\":false}"), true);
        button(R.string.f6_scan_app, () -> scan(false), true);
        button(R.string.f6_scan_shizuku, () -> scan(true), true);
        flowConfig = field(R.string.ui_config, "{\"package\":\"org.actscope.probe\",\"steps\":[{\"action\":\"launch\",\"wait_ms\":1000}]}", true);
        button(R.string.ui_start, () -> {
            if (ProbeAccessibilityService.active == null) throw new IllegalStateException(getString(R.string.f6_a11y_required));
            ProbeAccessibilityService.active.startFlow(withRun(text(flowConfig))); message(getString(R.string.ui_started));
        });
        button(R.string.ui_stop, () -> { if (ProbeAccessibilityService.active != null) ProbeAccessibilityService.active.stopFlow(); });
        layout = mainLayout;
        exportButton = button(R.string.export_evidence, this::startExport);
        exportStatus = label(UiStatus.render(this, ProbeConfig.prefs(this).getString("export_message", "{}"), R.string.export_hint));
        if (savedInstanceState != null) {
            EditText[] fields = {endpoint, run, token, period, watchConfig, scanConfig, flowConfig};
            for (int n = 0; n < fields.length; n++) if (savedInstanceState.containsKey("draft_" + n)) fields[n].setText(savedInstanceState.getString("draft_" + n));
            f6Channel.setSelection(savedInstanceState.getInt("f6_channel", 0));
            f1Baseline.setChecked(savedInstanceState.getBoolean("f1_baseline", false));
        }
        Shizuku.addRequestPermissionResultListener(permissionListener);
        Shizuku.addBinderDeadListener(binderDead);
        Shizuku.addBinderReceivedListenerSticky(binderReceived);
        handler.post(pollWatch); refresh();
    }
    @Override protected void onResume() {
        super.onResume();
        updateFloatingOverlay();
        if (shizukuStatus != null) autoConnectShell();
        if (f6Status != null) refreshF6();
        if (state != null) refresh();
    }
    @Override protected void onSaveInstanceState(Bundle out) {
        ProbeConfig.prefs(this).edit().putString("experiment_run_id", text(run)).apply();
        EditText[] fields = {endpoint, run, token, period, watchConfig, scanConfig, flowConfig};
        for (int n = 0; n < fields.length; n++) out.putString("draft_" + n, text(fields[n]));
        out.putInt("f6_channel", f6Channel.getSelectedItemPosition());
        out.putBoolean("f1_baseline", f1Baseline.isChecked());
        super.onSaveInstanceState(out);
    }
    private boolean shellConnected() { return shell != null && shell.asBinder().isBinderAlive(); }
    private void updateFloatingOverlay() {
        if (overlayEnabled == null || floatingOverlay == null) return;
        if (!overlayEnabled.isChecked()) {
            floatingOverlay.hide(); updateOverlayStatus(); return;
        }
        if (Settings.canDrawOverlays(this)) {
            applyFloatingOverlay();
            return;
        }
        updateOverlayStatus();
        if (!ProbeConfig.prefs(this).getBoolean("overlay_prompt_shown", false)) {
            ProbeConfig.prefs(this).edit().putBoolean("overlay_prompt_shown", true).apply();
            new AlertDialog.Builder(this).setTitle(R.string.overlay_permission_title)
                .setMessage(R.string.overlay_permission_explanation)
                .setPositiveButton(R.string.overlay_open_settings, (dialog, which) -> openOverlaySettings())
                .setNegativeButton(android.R.string.cancel, null).show();
        }
    }
    private void applyFloatingOverlay() {
        try {
            floatingOverlay.show();
            updateOverlayStatus();
        } catch (RuntimeException e) {
            floatingOverlay.hide();
            overlayStatus.setText(getString(R.string.overlay_unavailable, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
        }
    }
    private void updateOverlayStatus() {
        if (overlayStatus == null || overlayEnabled == null) return;
        if (!overlayEnabled.isChecked()) overlayStatus.setText(R.string.overlay_status_off);
        else if (Settings.canDrawOverlays(this)) overlayStatus.setText(R.string.overlay_status_on);
        else overlayStatus.setText(R.string.overlay_status_permission_needed);
    }
    private void openOverlaySettings() {
        if (Settings.canDrawOverlays(this)) { applyFloatingOverlay(); return; }
        Intent intent = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:" + getPackageName()));
        if (intent.resolveActivity(getPackageManager()) == null) {
            showError(new IllegalStateException(getString(R.string.overlay_settings_unavailable)));
            return;
        }
        try { startActivity(intent); }
        catch (ActivityNotFoundException e) { showError(new IllegalStateException(getString(R.string.overlay_settings_unavailable))); }
    }
    private boolean shizukuAuthorized() {
        try { return Shizuku.pingBinder() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED; }
        catch (RuntimeException e) { return false; }
    }
    private void autoConnectShell() {
        if (destroyed) return;
        if (shizukuAuthorized()) { if (!shellConnected()) bindShell(); else shizukuStatus.setText(R.string.shizuku_connected); }
        else shizukuStatus.setText(Shizuku.pingBinder() ? R.string.shizuku_not_authorized : R.string.shizuku_not_running);
    }
    private void bindShell() {
        if (destroyed || bound || shellConnected()) return;
        try {
            bound = true; shizukuStatus.setText(R.string.shizuku_connecting);
            handler.postDelayed(connectionTimeout, 15000);
            Shizuku.bindUserService(serviceArgs, connection);
        } catch (RuntimeException e) {
            bound = false; handler.removeCallbacks(connectionTimeout);
            shizukuStatus.setText(getString(R.string.shizuku_connect_failed, e.getMessage()));
            if (pendingF6Context != null) { pendingF6Context = null; f6Error(e); }
        }
    }
    private void unbindShell() {
        handler.removeCallbacks(connectionTimeout);
        if (bound) { try { Shizuku.unbindUserService(serviceArgs, connection, false); } catch (RuntimeException ignored) { } }
        bound = false; shell = null;
    }
    private void connectionLost() {
        if (destroyed) return;
        serviceHasF1Watch = false; f1Generation++;
        unbindShell(); shizukuStatus.setText(R.string.shizuku_disconnected);
        if (pendingF6Context != null) { pendingF6Context = null; f6Error(new IllegalStateException(getString(R.string.shizuku_disconnected))); }
    }
    private IUserService requireShell() {
        if (!shellConnected()) throw new IllegalStateException(getString(R.string.shizuku_required));
        return shell;
    }
    private void startF1Watch() throws Exception {
        IUserService connected = requireShell();
        JSONObject options = new JSONObject(withRun(text(watchConfig))).put("normal_baseline_verified", f1Baseline.isChecked());
        ProbeConfig.prefs(this).edit().putString("f1_manual_options", text(watchConfig)).apply();
        if (serviceHasF1Watch && (f1Evidence.optBoolean("watch_running", false) || f1Evidence.optBoolean("replacement_running", false)) && BuildConfig.PROBE_BUILD_ID.equals(f1Evidence.optString("build_id"))) throw new IllegalStateException(getString(R.string.f1_error_watch_running));
        f1Evidence = new JSONObject(); refreshF1(f1Evidence);
        runF1Action(generation -> {
            F1Fixtures fixtures = F1Fixtures.load(this);
            recordF1Result(connected.startManualWatch(fixtures.configuration(options).toString(), fixtures.replacement), generation);
        });
    }
    private void attemptF1Hijack() throws Exception {
        JSONObject row = selectedF1Candidate();
        if (row == null) throw new IllegalStateException(getString(R.string.f1_invalid_candidate));
        if (!text(run).equals(f1Evidence.optString("run_id")) || !BuildConfig.PROBE_BUILD_ID.equals(f1Evidence.optString("build_id"))) throw new IllegalStateException(getString(R.string.f1_run_changed));
        IUserService connected = requireShell();
        String watchId = f1Evidence.getString("watch_id"), candidateId = row.getString("candidate_id");
        boolean baselineVerified = f1Baseline.isChecked();
        runF1Action(generation -> recordF1Result(connected.attemptHijack(watchId, candidateId, baselineVerified), generation));
    }
    private interface F1Action { void run(int generation) throws Exception; }
    private void runF1Action(F1Action action) throws Exception {
        if (f1Busy) throw new IllegalStateException(getString(R.string.f1_working));
        f1Busy = true; f1Generation++; f1OperationError = ""; refreshF1(f1Evidence);
        final int generation = f1Generation;
        executor.execute(() -> {
            try { action.run(generation); }
            catch (Exception e) {
                handler.post(() -> { if (!destroyed) { f1OperationError = errorText(e); refreshF1(f1Evidence); } }); showError(e);
            } finally { handler.post(() -> { f1Busy = false; if (!destroyed) refreshF1(f1Evidence); }); }
        });
    }
    private void recordF1Result(String value, int generation) throws Exception {
        JSONObject result = new JSONObject(value);
        if (result.has("error")) throw new IOException(f1Problem(result.optString("error_code", "f1_operation_failed")));
        if (!"actscope.device.f1.v1".equals(result.optString("schema")) || !result.has("watch_id")) {
            handler.post(() -> { if (!destroyed && generation == f1Generation) { serviceHasF1Watch = false; refreshF1(f1Evidence); } }); return;
        }
        handler.post(() -> {
            if (destroyed || generation != f1Generation) return;
            serviceHasF1Watch = true;
            ProbeConfig.prefs(this).edit().putString("f1_result", value).apply(); refreshF1(result);
        });
    }
    private String f1Problem(String code) {
        if ("requires_shell_uid_2000".equals(code)) return getString(R.string.f1_error_uid);
        if ("watch_already_running".equals(code)) return getString(R.string.f1_error_watch_running);
        if ("replacement_already_armed".equals(code)) return getString(R.string.f1_error_replacement_running);
        if ("watch_changed".equals(code) || "watch_missing".equals(code)) return getString(R.string.f1_error_watch_changed);
        if ("candidate_changed".equals(code) || "candidate_not_ready".equals(code)) return getString(R.string.f1_error_candidate_changed);
        if ("target_changed".equals(code) || "target_disappeared_or_redirected".equals(code)) return getString(R.string.f1_error_target_changed);
        return getString(R.string.f1_error_generic, code);
    }
    private void refreshF1(JSONObject result) {
        if (destroyed || f1Status == null) return;
        f1Evidence = result;
        JSONArray rows = result.optJSONArray("candidates"); if (rows == null) rows = new JSONArray();
        String signature = rows.toString();
        if (!signature.equals(displayedCandidates)) {
            displayedCandidates = signature; String previous = selectedCandidateId;
            f1Rows.clear(); List<String> labels = new ArrayList<>(); int selected = -1, ready = -1;
            for (int i = 0; i < rows.length(); i++) {
                JSONObject row = rows.optJSONObject(i); if (row == null) continue;
                f1Rows.add(row); labels.add(row.optString("path") + "\n" + f1CandidateLabel(row));
                if (previous.equals(row.optString("candidate_id"))) selected = f1Rows.size() - 1;
                if (ready < 0 && "ready".equals(row.optString("status"))) ready = f1Rows.size() - 1;
            }
            if (labels.isEmpty()) labels.add(getString(R.string.f1_no_candidates));
            if (selected >= 0 && !"ready".equals(f1Rows.get(selected).optString("status")) && ready >= 0) selected = ready;
            if (selected < 0) selected = ready < 0 ? 0 : ready;
            selectedCandidateId = selected < f1Rows.size() ? f1Rows.get(selected).optString("candidate_id") : "";
            ArrayAdapter<String> adapter = new ArrayAdapter<>(this, R.layout.f1_candidate_item, labels);
            adapter.setDropDownViewResource(R.layout.f1_candidate_item);
            f1Candidates.setAdapter(adapter);
            f1Candidates.setSelection(selected);
        }
        String phase = result.optString("phase", "idle"), status;
        if (f1Busy) status = getString(R.string.f1_working);
        else if (!result.has("watch_id")) status = getString(R.string.f1_idle);
        else if (shellConnected() && !serviceHasF1Watch) status = getString(R.string.f1_error_watch_changed);
        else if ("baseline_scan".equals(phase)) status = getString(R.string.f1_baseline_scanning);
        else if (result.optBoolean("watch_running")) status = getString(R.string.f1_monitoring, result.optInt("initial_apk_count"), result.optInt("last_scan_apk_count"), rows.length());
        else status = getString(R.string.f1_stopped, rows.length());
        if (result.has("watch_id")) status += "\n" + getString(R.string.f1_scope_summary, result.optInt("last_scan_error_count"), result.optInt("candidate_entries_dropped") + result.optInt("candidate_entries_omitted_from_status"));
        JSONObject pending = result.optJSONObject("pending_replacement");
        if (pending != null) {
            String state = pending.optString("state");
            if ("waiting_for_next_upload".equals(state)) status += "\n" + (serviceHasF1Watch && shellConnected() ? getString(R.string.f1_waiting_upload, pending.optString("directory", pending.optString("path"))) : getString(R.string.f1_error_watch_changed));
            else if ("timed_out".equals(state)) status += "\n" + getString(R.string.f1_wait_timeout);
            else if ("cancelled".equals(state)) status += "\n" + getString(R.string.f1_wait_cancelled);
            else if ("failed".equals(state)) status += "\n" + getString(R.string.f1_attempt_failed, f1Problem(pending.optString("reason")));
        }
        JSONObject attempt = result.optJSONObject("last_attempt");
        if (attempt != null) status += "\n" + (attempt.optBoolean("replacement_succeeded") ? getString(R.string.f1_attempt_success, attempt.optString("path")) : getString(R.string.f1_attempt_failed, f1Problem(attempt.optString("reason"))));
        if (!f1OperationError.isEmpty()) status += "\n" + getString(R.string.error_detail, f1OperationError);
        f1Status.setText(status); f1Start.setEnabled(!f1Busy && !(serviceHasF1Watch && BuildConfig.PROBE_BUILD_ID.equals(result.optString("build_id")) && (result.optBoolean("watch_running") || result.optBoolean("replacement_running"))));
        updateF1Selection();
    }
    private JSONObject selectedF1Candidate() {
        for (JSONObject row : f1Rows) if (selectedCandidateId.equals(row.optString("candidate_id"))) return row;
        return null;
    }
    private String f1CandidateLabel(JSONObject row) {
        switch (row.optString("status")) {
            case "ready": return getString(R.string.f1_candidate_ready);
            case "replaced": return getString(R.string.f1_candidate_replaced);
            case "failed": return getString(R.string.f1_candidate_failed);
            case "stale": case "disappeared": return getString(R.string.f1_candidate_stale);
            default: return getString(R.string.f1_candidate_stale);
        }
    }
    private void updateF1Selection() {
        if (destroyed || f1Attempt == null || f1Path == null) return;
        JSONObject row = selectedF1Candidate(); String path = row == null ? getString(R.string.f1_no_candidates) : row.optString("path") + "\n"
            + getString(R.string.f1_watch_directory, new File(row.optString("path")).getParent()) + "\n" + f1CandidateLabel(row);
        if (!path.contentEquals(f1Path.getText())) f1Path.setText(path);
        f1Attempt.setEnabled(!f1Busy && serviceHasF1Watch && shellConnected() && row != null && !f1Evidence.optBoolean("replacement_running")
            && text(run).equals(f1Evidence.optString("run_id")) && BuildConfig.PROBE_BUILD_ID.equals(f1Evidence.optString("build_id")));
    }
    private void startBuiltinF6() throws Exception {
        if (f6Scanning || pendingF6Context != null) throw new IllegalStateException(getString(R.string.f6_already_running));
        JSONObject context = new JSONObject(withRun("{}"));
        boolean running = Shizuku.pingBinder(), authorized = shizukuAuthorized();
        F6StartGate.Decision decision = F6StartGate.choose(f6Channel.getSelectedItemPosition(), running, authorized, shellConnected());
        if (decision == F6StartGate.Decision.SHIZUKU_NOT_RUNNING) throw new IllegalStateException(getString(R.string.shizuku_start_first));
        if (decision == F6StartGate.Decision.SHIZUKU_PERMISSION_REQUIRED) throw new IllegalStateException(getString(R.string.shizuku_denied));
        if (decision == F6StartGate.Decision.WAIT_FOR_SHIZUKU) {
            pendingF6Context = context; UiStatus.f6(this, "f6_wait_shizuku"); refreshF6(); bindShell(); return;
        }
        startFileScan(context, decision == F6StartGate.Decision.SHIZUKU);
    }
    private void startFileScan(JSONObject context, boolean privileged) throws Exception {
        JSONObject config = BuiltinRules.load(this, "f6/file_rules.json");
        for (String key : new String[]{"run_id", "instance_id", "build_id"}) config.put(key, context.get(key));
        final IUserService connected = privileged ? requireShell() : null;
        if (ProbeAccessibilityService.active != null) ProbeAccessibilityService.active.stopFlow();
        f6Scanning = true; scanStarted = SystemClock.elapsedRealtime();
        // The localized channel is rendered afresh, including after a system-language change.
        UiStatus.f6(this, "f6_scanning", privileged ? "shizuku" : "app"); refreshF6();
        executor.execute(() -> {
            try {
                JSONObject result;
                try {
                    result = privileged ? new JSONObject(connected.scanFiles(config.toString())) : FileProbe.scan(config, "ordinary_app_uid=" + android.os.Process.myUid());
                    if (result.has("error")) throw new IOException(result.optString("error"));
                } catch (Exception e) {
                    result = new JSONObject().put("error", e.toString()).put("file_scan_complete", false).put("files", new JSONArray())
                        .put("access_errors", new JSONArray().put(new JSONObject().put("reason", e.toString())));
                }
                for (String key : new String[]{"run_id", "instance_id", "build_id"}) result.put(key, context.get(key));
                result.put("schema", "actscope.device.f6.v1").put("failure", "F6").put("builtin_rule_count", 188)
                    .put("ui", new JSONArray()).put("ui_scan_complete", false).put("batch_execution_complete", false);
                UiStatus.f6(this, "f6_discovering");
                JSONArray discovery = BuiltinRules.discover(this); result.put("package_checks", discovery).put("ui_execution_status", "pending");
                ProbeConfig.prefs(this).edit().putString("f6_result", result.toString()).putString("f6_context", context.toString()).putString("ui_trace", "{}").commit();
                JSONObject ready = result;
                handler.post(() -> {
                    f6Scanning = false;
                    if (destroyed) return;
                    try { beginBuiltinUi(context, discovery, ready); } catch (Exception e) { f6Error(e); }
                    refreshF6();
                });
            } catch (Exception e) { f6Scanning = false; f6Error(e); }
        });
    }
    private void beginBuiltinUi(JSONObject context, JSONArray discovery, JSONObject result) throws Exception {
        int ready = 0;
        for (int n = 0; n < discovery.length(); n++) if ("ready".equals(discovery.getJSONObject(n).optString("status"))) ready++;
        int files = result.optJSONArray("files") == null ? 0 : result.getJSONArray("files").length();
        int errors = result.optJSONArray("access_errors") == null ? 0 : result.getJSONArray("access_errors").length();
        if (ready == 0) {
            result.put("batch_execution_complete", true).put("ui_execution_status", "no_runnable_installed_targets");
            ProbeConfig.prefs(this).edit().putString("f6_result", result.toString()).apply();
            UiStatus.f6(this, "f6_no_targets", files, errors); return;
        }
        if (ProbeAccessibilityService.active == null) {
            result.put("ui_execution_status", "needs_accessibility");
            ProbeConfig.prefs(this).edit().putString("f6_result", result.toString()).apply();
            UiStatus.f6(this, "f6_needs_a11y", files, errors, ready);
            new AlertDialog.Builder(this).setTitle(R.string.f6_a11y_title).setMessage(R.string.f6_a11y_dialog)
                .setPositiveButton(R.string.open_accessibility, (dialog, which) -> openAccessibility())
                .setNegativeButton(android.R.string.cancel, null).show();
            return;
        }
        ProbeAccessibilityService.active.startBuiltinBatch(context, discovery, result);
    }
    private void resumeBuiltinF6() throws Exception {
        if (f6Scanning || pendingF6Context != null) throw new IllegalStateException(getString(R.string.f6_already_running));
        JSONObject result = new JSONObject(ProbeConfig.prefs(this).getString("f6_result", "{}"));
        JSONObject context = new JSONObject(ProbeConfig.prefs(this).getString("f6_context", "{}"));
        if (!context.optString("run_id", "").equals(text(run))) throw new IllegalStateException(getString(R.string.f6_run_mismatch));
        for (String key : new String[]{"run_id", "instance_id", "build_id"}) {
            if (!context.has(key) || !result.has(key) || !context.getString(key).equals(result.getString(key))) throw new IllegalStateException(getString(R.string.f6_identity_mismatch));
        }
        if (!ProbeConfig.instance(this).equals(context.getString("instance_id")) || !BuildConfig.PROBE_BUILD_ID.equals(context.getString("build_id"))) throw new IllegalStateException(getString(R.string.f6_identity_mismatch));
        if (ProbeAccessibilityService.active == null) throw new IllegalStateException(getString(R.string.f6_a11y_required));
        beginBuiltinUi(context, BuiltinRules.discover(this), result); refreshF6();
    }
    private void scan(boolean privileged) throws Exception {
        if (f6Scanning || pendingF6Context != null) throw new IllegalStateException(getString(R.string.f6_already_running));
        String config = withRun(text(scanConfig)); final IUserService connected = privileged ? requireShell() : null;
        ProbeConfig.prefs(this).edit().putString("scan_config", config).remove("f6_context").putString("ui_trace", "{}").apply();
        f6Scanning = true; scanStarted = SystemClock.elapsedRealtime();
        UiStatus.f6(this, "f6_scanning", privileged ? "shizuku" : "app"); refreshF6();
        executor.execute(() -> {
            try {
                String value = privileged ? connected.scanFiles(config) : FileProbe.scan(new JSONObject(config), "ordinary_app_uid=" + android.os.Process.myUid()).toString();
                JSONObject result = new JSONObject(value); saveResult("f6_result", value);
                if (result.has("error")) throw new IOException(result.optString("error"));
                UiStatus.f6(this, "f6_files_only", result.getJSONArray("files").length(), result.getJSONArray("access_errors").length());
            } catch (Exception e) { f6Error(e); }
            finally { f6Scanning = false; handler.post(this::refreshF6); }
        });
    }
    private void refreshF6() {
        if (destroyed || f6Status == null) return;
        boolean busy = f6Scanning || pendingF6Context != null || exporting || uiRunning();
        String value = UiStatus.f6(this);
        if (f6Scanning) value += "\n" + getString(R.string.f6_scan_elapsed, (SystemClock.elapsedRealtime() - scanStarted) / 1000);
        f6Status.setText(value); f6Progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        f6Start.setEnabled(!busy); f6Resume.setEnabled(!busy); f6Channel.setEnabled(!busy);
    }
    private boolean uiRunning() { return ProbeAccessibilityService.active != null && ProbeAccessibilityService.active.isBuiltinRunning(); }
    private void f6Error(Exception e) {
        UiStatus.f6(this, "f6_failure", errorText(e));
        handler.post(() -> { if (destroyed) return; refreshF6(); new AlertDialog.Builder(this).setTitle(R.string.f6_error_title).setMessage(errorText(e)).setPositiveButton(android.R.string.ok, null).show(); });
    }
    private void openAccessibility() { startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)); }
    private void saveResult(String key, String value) throws Exception {
        new JSONObject(value); ProbeConfig.prefs(this).edit().putString(key, value).commit(); message(value);
    }
    private String withRun(String json) throws Exception {
        String id = text(run);
        if (id.isEmpty()) { id = ExperimentIds.local(); run.setText(id); }
        if (!ExperimentIds.valid(id)) throw new IllegalArgumentException(getString(R.string.run_invalid));
        ProbeConfig.prefs(this).edit().putString("experiment_run_id", id).commit();
        return new JSONObject(json).put("run_id", id).put("instance_id", ProbeConfig.instance(this)).put("build_id", BuildConfig.PROBE_BUILD_ID).toString();
    }
    private void startExport() throws Exception {
        if (exporting) return;
        if (f6Scanning || pendingF6Context != null || uiRunning()) throw new IllegalStateException(getString(R.string.export_wait_f6));
        if (Build.VERSION.SDK_INT <= 28 && checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{android.Manifest.permission.WRITE_EXTERNAL_STORAGE}, 2002); return;
        }
        exporting = true; exportButton.setEnabled(false); exportStatus.setText(R.string.export_preparing); refreshF6();
        executor.execute(() -> {
            try {
                JSONObject report = prepareExport();
                String saved = UiStatus.encode("export_saved", report.getString("directory"), report.getInt("screenshots_exported"), report.getInt("screenshots_unavailable"));
                ProbeConfig.prefs(this).edit().putString("export_message", saved).commit();
                handler.post(() -> { if (!destroyed) {
                    exportStatus.setText(UiStatus.render(this, saved, R.string.export_hint));
                    Toast.makeText(this, getString(R.string.export_done), Toast.LENGTH_LONG).show();
                } });
            } catch (Exception e) {
                handler.post(() -> { if (!destroyed) exportStatus.setText(getString(R.string.error_detail, errorText(e))); }); showError(e);
            } finally { handler.post(() -> { exporting = false; if (!destroyed) { exportButton.setEnabled(true); refreshF6(); } }); }
        });
    }
    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] granted) {
        super.onRequestPermissionsResult(request, permissions, granted);
        if (request != 2002) return;
        if (granted.length > 0 && granted[0] == PackageManager.PERMISSION_GRANTED) {
            try { startExport(); } catch (Exception e) { showError(e); }
        } else showError(new IOException(getString(R.string.export_storage_denied)));
    }
    private JSONObject prepareExport() throws Exception {
        if (shellConnected()) { try { String value = shell.status(); if ("actscope.device.f1.v1".equals(new JSONObject(value).optString("schema"))) ProbeConfig.prefs(this).edit().putString("f1_result", value).commit(); } catch (Exception ignored) { } }
        JSONObject bundle = new JSONObject().put("schema", "actscope.device.bundle.v1").put("exported_at_device", System.currentTimeMillis())
            .put("run_id", ProbeConfig.prefs(this).getString("experiment_run_id", "")).put("instance_id", ProbeConfig.instance(this)).put("build_id", BuildConfig.PROBE_BUILD_ID);
        for (String key : new String[]{"f1_result", "f6_result", "ui_trace"}) bundle.put(key, new JSONObject(ProbeConfig.prefs(this).getString(key, "{}")));
        JSONObject evidenceExport = BuiltinUiRunner.exportEvidence(this, bundle.getJSONObject("ui_trace"));
        bundle.put("ui_evidence", evidenceExport.getJSONArray("items")); evidenceExport.remove("items"); bundle.put("ui_evidence_export", evidenceExport);
        try (TelemetryStore db = new TelemetryStore(this)) { bundle.put("telemetry_history", db.export()).put("pending_uploads", db.queued()); }
        return DownloadEvidence.export(this, bundle);
    }
    private void refresh() {
        try (TelemetryStore db = new TelemetryStore(this)) {
            message(getString(R.string.status_summary, UiStatus.value(this, ProbeConfig.prefs(this).getBoolean("sampling", false)), db.queued(),
                UiStatus.value(this, Telemetry.enabled(this)), UiStatus.value(this, ProbePermissions.deviceAdminEnabled(this)),
                UiStatus.value(this, ProbePermissions.notificationListenerEnabled(this)),
                UiStatus.render(this, ProbeConfig.prefs(this).getString("telemetry_message", "{}"), R.string.no_sample)));
        }
    }
    private String errorText(Exception e) { return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(); }
    private void showError(Exception e) {
        handler.post(() -> { if (!destroyed) { message(getString(R.string.error_detail, errorText(e))); new AlertDialog.Builder(this).setTitle(R.string.error_title).setMessage(errorText(e)).setPositiveButton(android.R.string.ok, null).show(); } });
    }
    private interface Action { void run() throws Exception; }
    private void background(Action action) { executor.execute(() -> { try { action.run(); } catch (Exception e) { showError(e); } }); }
    private TextView label(int text) { return label(getString(text)); }
    private TextView label(String text) { TextView v = new TextView(this); v.setText(text); v.setTextSize(15); v.setPadding(0, 14, 0, 10); layout.addView(v); return v; }
    private EditText field(int title, String value, boolean multiline) {
        label(title); EditText v = new EditText(this); v.setText(value); v.setSingleLine(!multiline);
        if (multiline) { v.setMinLines(3); v.setTextSize(12); } layout.addView(v); return v;
    }
    private String text(EditText v) { return v.getText().toString().trim(); }
    private Button button(int title, Action action) { return button(title, action, false); }
    private Button button(int title, Action action, boolean f6) {
        Button b = new Button(this); b.setText(title);
        b.setOnClickListener(v -> { try { action.run(); } catch (Exception e) { if (f6) f6Error(e); else showError(e); } });
        layout.addView(b); return b;
    }
    private void message(String text) { handler.post(() -> { if (!destroyed && state != null) state.setText(text); }); }
    @Override protected void onDestroy() {
        destroyed = true; handler.removeCallbacks(pollWatch); handler.removeCallbacks(connectionTimeout);
        if (floatingOverlay != null) floatingOverlay.hide();
        Shizuku.removeRequestPermissionResultListener(permissionListener); Shizuku.removeBinderReceivedListener(binderReceived); Shizuku.removeBinderDeadListener(binderDead);
        unbindShell(); executor.shutdownNow(); statusExecutor.shutdownNow(); super.onDestroy();
    }

    private static final class FloatingOverlay {
        private final Context context;
        private final WindowManager windowManager;
        private View dot;

        FloatingOverlay(Context context) {
            this.context = context.getApplicationContext();
            this.windowManager = (WindowManager) context.getSystemService(WINDOW_SERVICE);
        }

        void show() {
            if (!Settings.canDrawOverlays(context)) throw new SecurityException("Overlay permission is not granted");
            if (dot != null && dot.isAttachedToWindow()) return;
            GradientDrawable shape = new GradientDrawable();
            shape.setShape(GradientDrawable.OVAL);
            shape.setColor(0xFF00B8D9);
            View view = new View(context);
            view.setBackground(shape);
            WindowManager.LayoutParams params = new WindowManager.LayoutParams(
                10, 10, WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                    | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                    | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT);
            params.gravity = Gravity.TOP | Gravity.END;
            params.x = 8;
            params.y = 120;
            windowManager.addView(view, params);
            dot = view;
        }

        void hide() {
            if (dot == null) return;
            try { windowManager.removeView(dot); }
            catch (RuntimeException ignored) { }
            finally { dot = null; }
        }
    }
}
