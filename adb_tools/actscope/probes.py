"""Host probes. Oracles are centralized in actscope.oracles, never inferred from rc alone."""
from __future__ import annotations
import json
import re
import shlex
import time
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from .adapters import PlatformAdapter
from .executor import AdbExecutor, sha256_file
from .rules import parse_rules
from .store import RunStore, project_path, read_json, utc_now, write_json


def bounded(options: dict, key: str, default: float, minimum: float, maximum: float) -> float:
    value = float(options.get(key, default))
    if not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}")
    return value


def epoch_ms(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    return int(parsed.timestamp() * 1000)


def require_remote_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path or "\n" in path:
        raise ValueError("Device paths must be absolute and contain no NUL/newline")
    return path


def _nonce_response(executor: AdbExecutor, prefix: str = "ACTSCOPE") -> tuple[str, object, bool]:
    nonce = prefix + "_" + uuid.uuid4().hex
    result = executor.shell_args(["printf", "%s", nonce])
    return nonce, result, result.ok and result.stdout.strip() == nonce


def scan_apks(executor: AdbExecutor, roots: list[str], *, max_files: int = 1000, timeout_s: float = 30) -> tuple[dict, list[dict], bool]:
    if not roots:
        raise ValueError("At least one scan root is required")
    quoted = " ".join(shlex.quote(require_remote_path(root)) for root in roots)
    deadline = time.monotonic() + timeout_s
    result = executor.shell(f"find {quoted} -type f -iname '*.apk' -print", timeout_s=timeout_s)
    errors = []
    if result.stderr or not result.ok:
        errors.append({"operation": "find_apks", "stderr": result.stderr, "returncode": result.returncode, "timed_out": result.timed_out})
    paths = list(dict.fromkeys(line for line in result.stdout.splitlines() if line.startswith("/")))
    complete = result.ok and len(paths) <= max_files
    if len(paths) > max_files:
        errors.append({"operation": "find_apks", "error": "max_files_exceeded", "observed": len(paths), "limit": max_files})
    snapshot = {}
    for path in paths[:max_files]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            errors.append({"operation": "hash_apks", "error": "scan_budget_exhausted", "remaining_files": len(paths) - len(snapshot)})
            complete = False
            break
        quoted_path = shlex.quote(path)
        digest = executor.shell(f"sha256sum {quoted_path} && stat -c '%s|%y|%i' {quoted_path}", timeout_s=remaining)
        match = re.match(r"^([0-9a-fA-F]{64})\s", digest.stdout)
        if digest.ok and match:
            metadata = digest.stdout.splitlines()
            snapshot[path] = {"sha256": match.group(1).lower(), "stat": metadata[1] if len(metadata) > 1 else None}
        else:
            complete = False
            errors.append({"operation": "hash_apk", "path": path, "stderr": digest.stderr, "stdout": digest.stdout})
    return snapshot, errors, complete


def probe_f1(store: RunStore, executor: AdbExecutor, options: dict, active: bool, progress=None) -> dict:
    original = project_path(options["original_apk"], must_exist=True)
    replacement = project_path(options["replacement_apk"], must_exist=True)
    original_hash, replacement_hash = sha256_file(original), sha256_file(replacement)
    if original_hash == replacement_hash:
        raise ValueError("Original and replacement APKs must differ")
    duration = bounded(options, "duration_s", 30, 0.1, 3600)
    interval = bounded(options, "poll_s", 1, 0.1, 60)
    max_files = int(bounded(options, "max_files", 1000, 1, 10000))
    roots = options.get("roots", ["/"])
    scan_timeout = bounded(options, "scan_timeout_s", 30, 1, 120)
    remote_replacement = f"/data/local/tmp/actscope-{store.run_id}-{uuid.uuid4().hex}.apk"
    if active:
        if not options.get("owned_test_artifacts") or not (options.get("controlled_upload_id") or options.get("original_install_task_id")):
            raise ValueError("Active F1 requires owned_test_artifacts=true and a controlled_upload_id or already-known original_install_task_id")
        pushed = executor.run(["push", str(replacement), remote_replacement])
        if not pushed.ok:
            executor.shell_args(["rm", "-f", remote_replacement])
            return {"original_sha256": original_hash, "replacement_sha256": replacement_hash,
                    "errors": ["Cannot stage replacement APK"], "observation_complete": False}
    observations, errors, attempted = [], [], False
    coverage_complete = True
    try:
        baseline, baseline_errors, coverage_complete = scan_apks(executor, roots, max_files=max_files, timeout_s=scan_timeout)
        errors.extend(baseline_errors)
        store.append("f1_scan_baseline", {"apks": baseline, "roots": roots, "errors": baseline_errors})
        if progress:
            progress("baseline_complete", {"complete": coverage_complete, "apk_count": len(baseline), "errors": baseline_errors})
        previous = dict(baseline)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            snapshot, scan_errors, complete = scan_apks(executor, roots, max_files=max_files, timeout_s=min(scan_timeout, max(0.1, deadline - time.monotonic())))
            coverage_complete &= complete
            errors.extend(scan_errors)
            for path, fingerprint in snapshot.items():
                digest = fingerprint.get("sha256") if isinstance(fingerprint, dict) else fingerprint
                if previous.get(path) == fingerprint:
                    continue
                record = {"path": path, "sha256": digest, "observed_at": utc_now(),
                          "change": "new" if path not in previous else "rewritten",
                          "matches_owned_original": digest == original_hash, "replacement_attempted": False}
                if digest == original_hash and active:
                    # Re-check digest in the same remote shell immediately before controlled replacement.
                    qpath, qreplacement = shlex.quote(path), shlex.quote(remote_replacement)
                    command = (f"test ! -L {qpath} && current=$(sha256sum {qpath}) && "
                               f"test \"${{current%% *}}\" = {shlex.quote(original_hash)} && "
                               f"cp {qreplacement} {qpath} && sha256sum {qpath}")
                    copied = executor.shell(command)
                    attempted = record["replacement_attempted"] = True
                    record.update({"copy_transport_success": copied.ok, "after_copy": copied.stdout, "stderr": copied.stderr})
                observations.append(record)
                store.append("f1_candidate", record)
                if progress:
                    progress("candidate", record)
            previous = snapshot
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
    finally:
        if active:
            executor.shell_args(["rm", "-f", remote_replacement])
    return {"method": "host_adb", "active": active, "original_sha256": original_hash,
            "replacement_sha256": replacement_hash, "normal_baseline_verified": options.get("normal_baseline_verified", False),
            "requested_build_id": options.get("requested_build_id"), "replacement_build_id": options.get("replacement_build_id"),
            "simple_workflow": options.get("simple_workflow", False),
            "original_install_task_id": options.get("original_install_task_id", ""),
            "controlled_upload_id": options.get("controlled_upload_id", ""),
            "observed_install_task_id": "", "replacement_attempted": attempted,
            "install_completed": False, "installed_identity_verified": False,
            "legitimate_transform_excluded": False, "observation_complete": False,
            "scan_complete": coverage_complete, "scan_roots": roots, "duration_s": duration,
            "candidates": observations, "access_errors": errors,
            "limitations": ["Final installation task and installed build must be observed and imported separately.",
                            "Scanning covers shell-readable paths and tested time window only; no atomicity guarantee.",
                            "Filename newlines are unsupported by this host scan format."]}


def probe_f4(store: RunStore, executor: AdbExecutor, options: dict, active: bool = False) -> dict:
    phase = options.get("phase", "post")
    if phase == "baseline":
        if store.latest_event("session_ended"):
            raise ValueError("F4 baseline must be established before session return; use a new run for a new session")
        nonce, response, success = _nonce_response(executor, "ACTSCOPE_F4_BASELINE")
        baseline = {"serial": executor.serial, "command": shlex.join(response.argv), "success": success,
                    "response": response.stdout, "challenge": nonce, "issued_at_server_ms": epoch_ms(response.started_at)}
        write_json(store.path / "f4_baseline.json", baseline)
        store.append("f4_baseline", baseline)
        return {"baseline": baseline, "session_end_confirmed": False, "probe": {},
                "limitations": ["Baseline only; record platform session_ended then run phase=post without refreshing credentials."]}
    if phase != "post":
        raise ValueError("F4 phase must be baseline or post")
    baseline = read_json(store.path / "f4_baseline.json")
    end = store.latest_event("session_ended")
    if not end:
        raise ValueError("Record a confirmed platform session_ended event first")
    if baseline["serial"] != executor.serial:
        raise ValueError("F4 must reuse the baseline serial and old credentials")
    events = store.read_events()
    end_index = next(index for index, event in enumerate(events) if event["event_id"] == end["event_id"])
    if any(event["kind"] in {"debug_prepared", "session_reacquired", "session_started"} for event in events[end_index + 1:]):
        raise ValueError("A new debug/session event occurred after return; cannot label this as old authorization")
    if baseline.get("issued_at_server_ms", 0) >= epoch_ms(end["data"]["time"]):
        raise ValueError("F4 baseline must precede the confirmed session return time")
    if not options.get("old_authorization_confirmed"):
        raise ValueError("Confirm old_authorization_confirmed=true; do not refresh credentials or reconnect using new credentials")
    nonce, response, success = _nonce_response(executor, "ACTSCOPE_F4_POST")
    return {"session_end_server_ms": epoch_ms(end["data"]["time"]), "session_end_confirmed": True,
            "baseline": baseline, "probe": {"serial": executor.serial, "command": shlex.join(response.argv),
            "issued_at_server_ms": epoch_ms(response.started_at), "completed_at_server_ms": epoch_ms(utc_now()),
            "success": response.ok, "device_response_verified": success, "response": response.stdout,
            "challenge": nonce, "old_authorization": True, "reauthorized": False, "authorization_revoked": False},
            "limitations": ["A failed/filtered probe does not prove all old ADB capabilities were revoked."]}


def boot_identity(executor: AdbExecutor) -> dict | None:
    """Read a boot-scoped identity; failure stays unknown rather than fabricated."""
    boot = executor.shell_args(["cat", "/proc/sys/kernel/random/boot_id"])
    value = boot.stdout.strip()
    if boot.ok and re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
        return {"source": "kernel_boot_id", "value": value.lower()}
    count = executor.shell_args(["settings", "get", "global", "boot_count"])
    if count.ok and count.stdout.strip().isdigit():
        return {"source": "settings_boot_count", "value": count.stdout.strip()}
    return None


def probe_f3(store: RunStore, executor: AdbExecutor, options: dict, active: bool) -> dict:
    case = options.get("case", "reboot")
    if case not in {"reboot", "http_proxy"}:
        raise ValueError("F3 case must be reboot or http_proxy")
    if not active:
        return {"cases": [], "planned_case": case, "limitations": ["Dry run: no dangerous command executed; use --active and a recovery_plan in controlled testing."]}
    if not options.get("recovery_plan"):
        raise ValueError("Active F3 requires a documented independent recovery_plan")
    nonce, response, healthy = _nonce_response(executor, "ACTSCOPE_F3_BASELINE")
    base = {"id": f"{case}-{uuid.uuid4().hex[:8]}", "baseline_healthy": healthy,
            "attribution_verified": False, "observation_complete": False,
            "recovery_plan": options["recovery_plan"], "normal_recovery_failed": False,
            "platform_control_unavailable": False, "management_damage_verified": False}
    if not healthy:
        return {"cases": [{**base, "kind": "reboot" if case == "reboot" else "persistent_network",
                            "command_executed": False}], "limitations": ["Pre-probe ADB baseline failed"]}
    if case == "reboot":
        duration = bounded(options, "duration_s", 120, 1, 1800)
        interval = bounded(options, "poll_s", 5, 0.1, 60)
        before_boot = boot_identity(executor)
        command = executor.run(["reboot"])
        start = time.monotonic()
        checks, recovered, saw_unready, boundary_seen = [], False, False, False
        last_healthy = True
        while time.monotonic() - start < duration:
            time.sleep(min(interval, max(0, duration - (time.monotonic() - start))))
            boot = executor.shell_args(["getprop", "sys.boot_completed"])
            check_nonce, device, fresh = _nonce_response(executor, "ACTSCOPE_F3_RECOVERY")
            current_boot = boot_identity(executor) if fresh else None
            last_healthy = fresh and boot.ok and boot.stdout.strip() == "1"
            saw_unready |= not last_healthy
            comparable = before_boot is not None and current_boot is not None and before_boot["source"] == current_boot["source"]
            identity_changed = comparable and before_boot["value"] != current_boot["value"]
            # A response from the same old boot never establishes reboot recovery.
            # If boot IDs are unavailable, record the weaker observed unready→ready boundary.
            boundary = identity_changed or (not comparable and saw_unready and last_healthy)
            boundary_seen |= boundary
            checks.append({"at": utc_now(), "boot_completed": boot.stdout.strip(), "device_responded": fresh,
                           "boot_identity": current_boot, "boot_identity_changed": identity_changed,
                           "reboot_boundary_observed": boundary})
            if last_healthy and boundary:
                recovered = True
                break
        base.update({"kind": "reboot", "command": "adb -s <same-serial> reboot", "command_executed": command.ok,
                     "observed_seconds": time.monotonic() - start, "min_observation_seconds": duration,
                     "device_unavailable": not last_healthy, "device_recovered": recovered,
                     "recovered_via_existing_adb": recovered, "boot_identity_before": before_boot,
                     "reboot_boundary_observed": boundary_seen, "checks": checks, "observation_complete": recovered,
                     "recovery_evidence": "Observed reboot boundary, fresh ADB response and completed boot" if recovered else
                         "Reboot recovery not verified inside observation window; inspect boot transition and platform recovery evidence"})
        return {"cases": [base], "limitations": ["No automated reconnect or credential refresh is performed. Record platform control/normal recovery evidence before confirming harm.",
                     "A response from the original boot does not establish recovery; absent boot identities, an observed unready-to-ready transition is recorded as weaker boundary evidence."]}
    return _probe_proxy(store, executor, options, base)


def _probe_proxy(store: RunStore, executor: AdbExecutor, options: dict, base: dict) -> dict:
    phase = options.get("phase", "roundtrip")
    if phase not in {"roundtrip", "apply", "restore"}:
        raise ValueError("http_proxy phase must be roundtrip, apply or restore")
    snapshot_path = store.path / "f3_proxy_snapshot.json"
    if phase == "restore":
        snapshot = read_json(snapshot_path)
        if snapshot["serial"] != executor.serial:
            raise ValueError("Proxy restore serial differs from snapshot")
        before = executor.shell_args(["settings", "get", "global", "http_proxy"])
        result = _restore_proxy(executor, snapshot)
        return {"cases": [{**base, "kind": "persistent_network", "command": "settings restore global http_proxy",
                           "command_executed": result["command_success"], "configuration_changed": before.stdout.strip() != snapshot["value"],
                           "restoration": result, "setting_before_restore": before.stdout.strip(), "cleanup_confirmed": False,
                           "effect_verified": False, "persists_after_cleanup": False}],
                "limitations": ["Configuration readback alone does not prove a network effect or completed platform cleanup."]}
    proxy = str(options.get("proxy", ""))
    if not re.fullmatch(r"[A-Za-z0-9.-]+:[0-9]{1,5}", proxy) or not 1 <= int(proxy.rsplit(":", 1)[1]) <= 65535:
        raise ValueError("proxy must be a researcher-controlled host:port")
    if not options.get("controlled_endpoint"):
        raise ValueError("Set controlled_endpoint=true only for an endpoint under your control")
    if snapshot_path.exists() and read_json(snapshot_path).get("pending_restore"):
        raise ValueError("An earlier proxy change is pending restore; run phase=restore first")
    listed = executor.shell_args(["settings", "list", "global"])
    if not listed.ok:
        raise ValueError("Cannot establish original proxy state; refusing mutation")
    entries = dict(line.split("=", 1) for line in listed.stdout.splitlines() if "=" in line)
    snapshot = {"serial": executor.serial, "exists": "http_proxy" in entries,
                "value": entries.get("http_proxy", "null"), "recorded_at": utc_now(), "pending_restore": True}
    write_json(snapshot_path, snapshot)
    store.append("f3_proxy_snapshot", snapshot)
    applied, readback, restored = None, None, None
    try:
        applied = executor.shell_args(["settings", "put", "global", "http_proxy", proxy])
        readback = executor.shell_args(["settings", "get", "global", "http_proxy"])
        if phase == "roundtrip":
            time.sleep(bounded(options, "hold_s", 0, 0, 60))
    finally:
        if phase == "roundtrip":
            restored = _restore_proxy(executor, snapshot)
            snapshot["pending_restore"] = not restored["verified"]
            write_json(snapshot_path, snapshot)
    base.update({"kind": "persistent_network", "command": "settings put global http_proxy <controlled-endpoint>",
                 "command_executed": bool(applied and applied.ok), "configuration_changed": bool(readback and readback.ok and readback.stdout.strip() == proxy and proxy != snapshot["value"]),
                 "setting_before": snapshot, "setting_after": readback.stdout.strip() if readback else None,
                 "restoration": restored, "effect_verified": False, "cleanup_confirmed": False,
                 "persists_after_cleanup": False, "pending_restore": phase == "apply"})
    return {"cases": [base], "limitations": ["Readback is capability evidence. Import observed controlled network effect and cleanup/recovery evidence for the security oracle.",
                                             "Apply phase requires a later explicit restore; snapshot and exact recovery state are retained."]}


def _restore_proxy(executor: AdbExecutor, snapshot: dict) -> dict:
    args = ["settings", "put", "global", "http_proxy", snapshot["value"]] if snapshot["exists"] else ["settings", "delete", "global", "http_proxy"]
    restored = executor.shell_args(args)
    listed = executor.shell_args(["settings", "list", "global"])
    entries = dict(line.split("=", 1) for line in listed.stdout.splitlines() if "=" in line)
    verified = restored.ok and listed.ok and (("http_proxy" in entries and entries["http_proxy"] == snapshot["value"]) if snapshot["exists"] else "http_proxy" not in entries)
    snapshot["pending_restore"] = not verified
    write_json(executor.store.path / "f3_proxy_snapshot.json", snapshot)
    return {"command_success": restored.ok, "verified": verified, "stdout": restored.stdout, "stderr": restored.stderr}


def probe_f6(store: RunStore, executor: AdbExecutor, options: dict, active: bool = False) -> dict:
    root = require_remote_path(options.get("root", "/sdcard"))
    files, errors = [], []
    maximum = int(bounded(options, "max_files_per_directory", 100, 1, 10000))
    rules_paths = options.get("rules", [str(p.relative_to(project_path("rules"))) for p in sorted(project_path("rules").glob("*.txt"))])
    rules = []
    for path in rules_paths:
        candidate = project_path(path)
        if not candidate.exists():
            candidate = project_path(Path("rules") / path, must_exist=True)
        rules.extend(parse_rules(candidate, root))
    attribution = options.get("provenance", {})
    for rule in rules:
        qpath = shlex.quote(rule.path)
        result = executor.shell(f"if test -f {qpath}; then printf 'file\\n'; stat -c '%s' {qpath}; elif test -d {qpath}; then printf 'directory\\n'; else ls -ld {qpath}; fi")
        lines = result.stdout.splitlines()
        kind = lines[0] if lines and lines[0] in {"file", "directory"} else "missing"
        if kind == "missing":
            if "No such file" in result.stderr and "Permission denied" not in result.stderr:
                files.append({"path": rule.path, "kind": rule.kind, "exists": False, "app": rule.app})
            else:
                errors.append({"path": rule.path, "error": "permission_denied" if "Permission denied" in result.stderr else "unresolved", "stderr": result.stderr, "stdout": result.stdout})
            continue
        origin = attribution.get(rule.path, {})
        record = {"path": rule.path, "kind": kind, "exists": True, "readable": executor.shell(f"test -r {qpath}").ok, "app": rule.app,
                  "expected_cleanup": origin.get("expected_cleanup", False),
                  "attributed_to_prior_session": origin.get("attributed_to_prior_session", False),
                  "provenance_evidence": origin.get("provenance_evidence", ""),
                  "public_resource": origin.get("public_resource", False), "rule_source": rule.source, "rule_line": rule.line}
        if kind == "file":
            record["size"] = int(lines[1]) if len(lines) > 1 and lines[1].isdigit() else None
            if not result.ok:
                errors.append({"path": rule.path, "error": "metadata_unavailable", "stderr": result.stderr})
        files.append(record)
        if kind == "directory":
            listing = executor.shell(f"find {qpath} -type f -print", timeout_s=30)
            paths = listing.stdout.splitlines()
            if listing.stderr or not listing.ok or len(paths) > maximum:
                errors.append({"path": rule.path, "error": "partial_directory_scan", "stderr": listing.stderr, "limit": maximum})
            for child in paths[:maximum]:
                child_origin = attribution.get(child, origin)
                metadata = executor.shell_args(["stat", "-c", "%s|%Y", child])
                metadata_parts = metadata.stdout.strip().split("|")
                child_size = int(metadata_parts[0]) if metadata_parts and metadata_parts[0].isdigit() else None
                child_mtime = int(metadata_parts[1]) if len(metadata_parts) > 1 and metadata_parts[1].isdigit() else None
                if not metadata.ok:
                    errors.append({"path": child, "error": "metadata_unavailable", "stderr": metadata.stderr})
                files.append({"path": child, "kind": "file", "exists": True, "readable": executor.shell(f"test -r {shlex.quote(child)}").ok, "app": rule.app,
                              "expected_cleanup": child_origin.get("expected_cleanup", False),
                              "attributed_to_prior_session": child_origin.get("attributed_to_prior_session", False),
                              "provenance_evidence": child_origin.get("provenance_evidence", ""),
                              "public_resource": child_origin.get("public_resource", False), "rule_source": rule.source, "size": child_size, "mtime_seconds": child_mtime})
    store.append("f6_file_scan", {"files": files, "access_errors": errors})
    ui = read_json(options["ui_observation_file"]) if options.get("ui_observation_file") else []
    if not isinstance(ui, list):
        raise ValueError("ui_observation_file must contain a list of UI observations")
    if options.get("ui_script"):
        if not active:
            raise ValueError("Executing a UI script requires --active")
        execute_ui_script(store, executor, read_json(options["ui_script"]))
    return {"files": files, "ui": ui, "file_scan_complete": not errors,
            "ui_scan_complete": bool(options.get("ui_scan_complete") and options.get("ui_observation_file")),
            "access_errors": errors, "scan_root": root,
            "limitations": ["Legacy rule matches are candidates until prior-session provenance and cleanup requirement are supplied.",
                            "File contents are not collected. Empty directories/public resources are not residual user data.",
                            "UI scripts execute only after file scanning; UI semantics require observation evidence."]}


def execute_ui_script(store: RunStore, executor: AdbExecutor, steps: list[dict]) -> None:
    """Small deterministic UI runner; manual interpretation remains explicit."""
    if not isinstance(steps, list) or len(steps) > 200:
        raise ValueError("UI script must be a list with at most 200 steps")
    for index, step in enumerate(steps):
        action = step.get("action")
        if action == "wait":
            time.sleep(bounded(step, "seconds", 1, 0, 30))
            continue
        if action == "tap":
            args = ["input", "tap", str(int(step["x"])), str(int(step["y"]))]
        elif action == "swipe":
            args = ["input", "swipe", *(str(int(step[key])) for key in ["x1", "y1", "x2", "y2"]), str(int(bounded(step, "duration_ms", 300, 1, 10000)))]
        elif action == "keyevent":
            args = ["input", "keyevent", str(int(step["code"]))]
        elif action == "launch":
            component = step["component"]
            if not re.fullmatch(r"[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+", component):
                raise ValueError("Invalid activity component")
            args = ["am", "start", "-n", component]
        else:
            raise ValueError(f"Unsupported UI action at index {index}: {action}")
        result = executor.shell_args(args)
        store.append("ui_step", {"index": index, "step": step, "success": result.ok})
        if not result.ok:
            raise RuntimeError(f"UI step {index} failed; see command evidence")


def run_probe(store: RunStore, failure: str, options: dict, active: bool, *, progress=None) -> dict:
    adapter = PlatformAdapter(store)
    if adapter.capabilities()["remote_adb"] is False:
        method = {"method": "host_adb", "status": "not_applicable",
                  "reason": "Platform configuration declares remote ADB unavailable"}
        store.append("method_unavailable", {"failure_mode": failure, **method})
        if failure in {"F1", "F6"}:
            # No host channel says nothing about App/Shizuku/manual coverage.
            return store.save_observation(failure, {"host_method_supported": False,
                      "method_results": [method], "alternative_methods_evaluated": False,
                      "limitations": ["Host ADB is unavailable; device-side Shizuku/App/UI methods remain unevaluated, so the overall failure mode is inconclusive."]})
        return store.save_observation(failure, {"supported": False, "method_results": [method],
                  "unsupported_reason": "F3/F4 test the platform's remote ADB channel, which is unavailable in this configured scope"})
    executor = adapter.connect_debug()
    implementations = {"F1": probe_f1, "F3": probe_f3, "F4": probe_f4, "F6": probe_f6}
    if failure not in implementations:
        raise ValueError("Host probe supports F1/F3/F4/F6; F2 uses deploy/import, F5/F7 use telemetry export/import")
    context = {"method": "host_adb", "serial": executor.serial}
    # F4's post-return operation remains the single explicit challenge probe.
    # F3 dry runs do not contact or mutate the device.
    if failure in {"F1", "F6"} or (failure == "F3" and active):
        identity = executor.shell_args(["id"])
        android = executor.shell_args(["getprop", "ro.build.version.release"])
        sdk = executor.shell_args(["getprop", "ro.build.version.sdk"])
        context.update({"execution_identity": identity.stdout.strip() if identity.ok else None,
                        "android_version": android.stdout.strip() if android.ok else None,
                        "sdk_version": sdk.stdout.strip() if sdk.ok else None})
        store.append("executor_context", context)
    if failure == "F1":
        observation = implementations[failure](store, executor, options, active, progress=progress)
    else:
        observation = implementations[failure](store, executor, options, active)
    observation["execution_context"] = context
    return store.save_observation(failure, observation)
