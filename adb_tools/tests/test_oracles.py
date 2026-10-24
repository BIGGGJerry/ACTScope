"""Offline regression tests for the security evidence boundary (no device needed)."""
import copy
import json
from pathlib import Path
import unittest

from actscope.oracles import evaluate

A, B = "a" * 64, "b" * 64


def f1():
    return dict(normal_baseline_verified=True, original_sha256=A, replacement_sha256=B,
                installed_sha256=B, original_install_task_id="task-1", observed_install_task_id="task-1",
                replacement_attempted=True, install_completed=True, legitimate_transform_excluded=True,
                installed_identity_verified=True, observation_complete=True)


def channel(name="official", blocked=False, official=True):
    return dict(name=name, sample_sha256=A, context_id="same-device-image-account", official=official,
                applicable=True, outcome="blocked" if blocked else "accepted", security_reason=blocked,
                prohibited_state_reached=not blocked, installed_sha256=A, identity_verified=True,
                check_completed=True, observation_window_seconds=60, completed=True)


def f2():
    return dict(sample_sha256=A, benign_baseline_ok=True,
                maliciousness=dict(confirmed=True, category="malware", basis="Controlled labelled research corpus"),
                channels=[channel()])


def f3case():
    return dict(id="reboot", kind="reboot", command="adb -s controlled-device reboot",
                baseline_healthy=True, command_executed=True, attribution_verified=True,
                observation_complete=True, observed_seconds=300, min_observation_seconds=300,
                device_unavailable=True, normal_recovery_failed=True,
                recovery_evidence="evidence/platform-recovery-attempts.json", administrator_recovery_required=True)


def f4():
    return dict(session_end_server_ms=1000, session_end_confirmed=True,
                baseline=dict(serial="same-device", command="shell date", success=True),
                probe=dict(serial="same-device", command="shell echo challenge-after-end", issued_at_server_ms=1001,
                           completed_at_server_ms=1005, success=True, device_response_verified=True,
                           old_authorization=True, reauthorized=False))


def event(seq, sampled=None):
    sampled = 11000 + seq * 1000 if sampled is None else sampled
    return dict(run_id="run-1", instance_id="instance-1", build_id="probe-debug", sequence=seq,
                sampled_at_device=sampled, received_at_server=sampled+100,
                clock_offset_ms=0, clock_uncertainty_ms=50, clock_sync_age_ms=100,
                boot_id="boot-1", elapsed_realtime_ms=sampled-1000, a11y_enabled=True,
                a11y_sampled_at=sampled, a11y_component="org.example/.ProbeA11y")


def telemetry():
    return dict(events=[event(1), event(2)], session_end_server_ms=10000,
                expected_instance_id="instance-1", expected_run_id="run-1", expected_build_id="probe-debug",
                baseline_telemetry_verified=True, initial_a11y_enabled=True, reauthorized=False,
                a11y_component="org.example/.ProbeA11y", min_fresh_events=2, clock_max_uncertainty_ms=2000)


def file_observation():
    return dict(files=[dict(path="/sdcard/Test/session.txt", kind="file", exists=True, size=3, readable=True,
                            expected_cleanup=True, attributed_to_prior_session=True,
                            provenance_evidence="Own previous-session output manifest", public_resource=False)],
                ui=[], file_scan_complete=True, ui_scan_complete=False, access_errors=[])


class CommonTests(unittest.TestCase):
    def test_example_files_are_labelled_and_match_expected_results(self):
        examples = Path(__file__).resolve().parents[1] / "configs" / "observations"
        for path in examples.glob("*.json"):
            observation = json.loads(path.read_text(encoding="utf-8"))
            metadata = observation.get("_example", {})
            if not metadata:
                continue
            with self.subTest(path=path.name):
                result = evaluate(metadata["failure_mode"], observation)
                self.assertEqual(result["status"], metadata["expected_status"])
                self.assertTrue(result["synthetic_fixture"])

    def test_empty_is_never_negative(self):
        for i in range(1, 8):
            with self.subTest(i=i):
                self.assertEqual(evaluate(f"F{i}", {})["status"], "inconclusive")

    def test_unsupported_is_not_applicable(self):
        for i in range(1, 8):
            self.assertEqual(evaluate(f"F{i}", {"supported": False})["status"], "not_applicable")

    def test_unknown_modes_are_errors(self):
        with self.assertRaises(ValueError):
            evaluate("F8", {})

    def test_evaluation_does_not_mutate_input(self):
        before = telemetry()
        observation = copy.deepcopy(before)
        evaluate("F7", observation)
        self.assertEqual(observation, before)

    def test_null_lists_are_inconclusive(self):
        for mode, key in (("F2", "channels"), ("F3", "cases"), ("F5", "events"), ("F6", "files")):
            self.assertEqual(evaluate(mode, {key: None})["status"], "inconclusive")


class F1Tests(unittest.TestCase):
    def test_replacement_in_original_task(self):
        self.assertEqual(evaluate("F1", f1())["status"], "confirmed")

    def test_different_install_task_is_not_hijack(self):
        o = f1(); o["observed_install_task_id"] = "own-separate-install"
        self.assertEqual(evaluate("F1", o)["status"], "inconclusive")

    def test_file_replacement_is_insufficient(self):
        o = f1(); o["install_completed"] = False
        self.assertEqual(evaluate("F1", o)["status"], "inconclusive")

    def test_baseline_is_required(self):
        o = f1(); o["normal_baseline_verified"] = False
        self.assertEqual(evaluate("F1", o)["status"], "inconclusive")

    def test_original_installed_is_scoped_negative(self):
        o = f1(); o["installed_sha256"] = A
        self.assertEqual(evaluate("F1", o)["status"], "not_observed")

    def test_identical_original_and_replacement_is_invalid(self):
        o = f1(); o["original_sha256"] = B
        self.assertEqual(evaluate("F1", o)["status"], "inconclusive")

    def test_trusted_build_marker_handles_instrumentation(self):
        o = f1(); o.update(installed_sha256="c"*64, requested_build_id="A", replacement_build_id="B", installed_build_id="B")
        self.assertEqual(evaluate("F1", o)["status"], "confirmed")
        o["legitimate_transform_excluded"] = False
        self.assertEqual(evaluate("F1", o)["status"], "inconclusive")

    def test_conflicting_build_and_hash_is_unknown(self):
        o = f1(); o.update(installed_sha256=A, requested_build_id="A", replacement_build_id="B", installed_build_id="B")
        self.assertEqual(evaluate("F1", o)["status"], "inconclusive")

    def test_final_original_build_marker_is_scoped_negative_without_hash(self):
        o = f1(); o.pop("installed_sha256")
        o.update(requested_build_id="A", replacement_build_id="B", installed_build_id="A")
        self.assertEqual(evaluate("F1", o)["status"], "not_observed")
        self.assertNotIn("installed_sha256", o)

    def test_original_marker_still_requires_complete_bound_verified_observation(self):
        original = f1(); original.pop("installed_sha256")
        original.update(requested_build_id="A", replacement_build_id="B", installed_build_id="A")
        for key, value in (("normal_baseline_verified", False), ("observed_install_task_id", "other-task"),
                           ("installed_identity_verified", False), ("install_completed", False),
                           ("observation_complete", False), ("replacement_build_id", "A")):
            o = dict(original); o[key] = value
            with self.subTest(key=key):
                self.assertEqual(evaluate("F1", o)["status"], "inconclusive")

    def test_known_hash_and_any_conflicting_declared_build_are_inconclusive(self):
        for digest, marker in ((A, "B"), (B, "A"), (A, "unexpected"), (B, "unexpected")):
            o = f1(); o.update(installed_sha256=digest, requested_build_id="A", replacement_build_id="B",
                              installed_build_id=marker)
            with self.subTest(digest=digest, marker=marker):
                self.assertEqual(evaluate("F1", o)["status"], "inconclusive")

    def test_original_marker_can_identify_a_transformed_original(self):
        o = f1(); o.update(installed_sha256="c" * 64, requested_build_id="A", replacement_build_id="B",
                            installed_build_id="A")
        self.assertEqual(evaluate("F1", o)["status"], "not_observed")

    def test_one_known_marker_can_still_contradict_opposite_hash(self):
        o = f1(); o.update(installed_sha256=B, requested_build_id="A", installed_build_id="A")
        self.assertEqual(evaluate("F1", o)["status"], "inconclusive")


class F2Tests(unittest.TestCase):
    def test_effectiveness_without_published_platform_policy(self):
        r = evaluate("F2", f2())
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["subresults"]["consistency"]["status"], "not_applicable")

    def test_window_bound_acceptance_is_reported(self):
        o = f2(); o["channels"][0]["check_completed"] = False
        r = evaluate("F2", o)["subresults"]["effectiveness"]
        self.assertEqual(r["status"], "confirmed")
        self.assertTrue(r["limitations"])

    def test_unknown_scan_and_no_window_is_unknown(self):
        o = f2(); o["channels"][0].update(check_completed=False, observation_window_seconds=0)
        self.assertEqual(evaluate("F2", o)["status"], "inconclusive")

    def test_resource_consumption_is_not_malware(self):
        o = f2(); o["maliciousness"]["category"] = "resource_abuse"
        self.assertEqual(evaluate("F2", o)["status"], "inconclusive")

    def test_ordinary_install_error_is_not_detection(self):
        o = f2(); o["channels"][0]["outcome"] = "installation_error"
        self.assertEqual(evaluate("F2", o)["status"], "inconclusive")

    def test_same_hash_different_channel_confirms_consistency_failure(self):
        o = f2(); o["channels"] = [channel(blocked=True), channel("adb", official=False)]
        r = evaluate("F2", o)["subresults"]
        self.assertEqual(r["effectiveness"]["status"], "not_observed")
        self.assertEqual(r["consistency"]["status"], "confirmed")

    def test_mismatched_sample_or_context_does_not_confirm(self):
        for key, value in (("sample_sha256", B), ("context_id", "other-device"), ("installed_sha256", B)):
            o = f2(); o["channels"] = [channel(blocked=True), channel("adb", official=False)]
            o["channels"][1][key] = value
            self.assertEqual(evaluate("F2", o)["subresults"]["consistency"]["status"], "inconclusive")

    def test_all_admitted_does_not_prove_bypass(self):
        o = f2(); o["channels"].append(channel("adb", official=False))
        self.assertEqual(evaluate("F2", o)["subresults"]["consistency"]["status"], "inconclusive")

    def test_all_security_blocked_is_negative(self):
        o = f2(); o["channels"] = [channel(blocked=True), channel("adb", blocked=True, official=False)]
        self.assertEqual(evaluate("F2", o)["status"], "not_observed")

    def test_warning_without_block_is_failure(self):
        o = f2(); o["channels"][0]["outcome"] = "warning_only"
        self.assertEqual(evaluate("F2", o)["status"], "confirmed")

    def test_normal_install_baseline_required(self):
        o = f2(); o["benign_baseline_ok"] = False
        self.assertEqual(evaluate("F2", o)["status"], "inconclusive")


class F3Tests(unittest.TestCase):
    def test_attributed_sustained_recovery_failure(self):
        self.assertEqual(evaluate("F3", {"cases": [f3case()]})["status"], "confirmed")

    def test_command_success_or_brief_disconnect_insufficient(self):
        for changes in ({"observed_seconds": 3}, {"attribution_verified": False}, {"recovery_evidence": ""},
                        {"normal_recovery_failed": False}):
            c = f3case(); c.update(changes)
            self.assertEqual(evaluate("F3", {"cases": [c]})["status"], "inconclusive")

    def test_normal_reboot_is_negative(self):
        c = f3case(); c.update(device_unavailable=False, device_recovered=True, normal_recovery_failed=False,
                              attribution_verified=False)
        self.assertEqual(evaluate("F3", {"cases": [c]})["status"], "not_observed")

    def test_persistent_configuration_requires_effect_and_cleanup(self):
        c = f3case(); c.update(kind="persistent_network", device_unavailable=False, normal_recovery_failed=False,
                              configuration_changed=True, effect_verified=True, cleanup_confirmed=True, persists_after_cleanup=True)
        self.assertEqual(evaluate("F3", {"cases": [c]})["status"], "confirmed")
        c["effect_verified"] = False
        self.assertEqual(evaluate("F3", {"cases": [c]})["status"], "inconclusive")
        c["effect_verified"] = True; c["cleanup_confirmed"] = False
        self.assertEqual(evaluate("F3", {"cases": [c]})["status"], "inconclusive")


class F4Tests(unittest.TestCase):
    def test_fresh_device_operation(self):
        self.assertEqual(evaluate("F4", f4())["status"], "confirmed")

    def test_devices_and_get_state_not_proof(self):
        for command in ("adb devices", "adb -s same-device get-state"):
            o = f4(); o["probe"]["command"] = command
            self.assertEqual(evaluate("F4", o)["status"], "inconclusive")

    def test_client_only_baseline_is_not_device_baseline(self):
        o = f4(); o["baseline"]["command"] = "adb devices"
        self.assertEqual(evaluate("F4", o)["status"], "inconclusive")

    def test_shell_word_in_serial_is_not_device_command(self):
        o = f4(); o["baseline"]["serial"] = "shell"; o["probe"]["serial"] = "shell"
        o["probe"]["command"] = "adb -s shell devices"
        self.assertEqual(evaluate("F4", o)["status"], "inconclusive")

    def test_full_adb_binary_and_global_arguments(self):
        o = f4(); o["probe"]["command"] = "/android/platform-tools/adb -H localhost -P 5037 -s same-device shell date"
        self.assertEqual(evaluate("F4", o)["status"], "confirmed")

    def test_wrong_serial_reauthorization_and_time_fail(self):
        for field, value in (("serial", "new-device"), ("reauthorized", True), ("issued_at_server_ms", 1000),
                             ("device_response_verified", False), ("old_authorization", False)):
            o = f4(); o["probe"][field] = value
            self.assertEqual(evaluate("F4", o)["status"], "inconclusive")

    def test_network_failure_is_not_revocation(self):
        o = f4(); o["probe"]["success"] = False
        self.assertEqual(evaluate("F4", o)["status"], "inconclusive")
        o["probe"]["authorization_revoked"] = True
        self.assertEqual(evaluate("F4", o)["status"], "not_observed")


class TelemetryTests(unittest.TestCase):
    def test_post_release_samples_confirm(self):
        self.assertEqual(evaluate("F5", telemetry())["status"], "confirmed")
        self.assertEqual(evaluate("F7", telemetry())["status"], "confirmed")

    def test_no_heartbeat_never_proves_cleanup(self):
        o = telemetry(); o["events"] = []
        for mode in ("F5", "F7"):
            self.assertEqual(evaluate(mode, o)["status"], "inconclusive")

    def test_delayed_old_samples_are_not_fresh(self):
        o = telemetry(); o["events"] = [event(1, 8000), event(2, 9000)]
        for e in o["events"]: e["received_at_server"] = 20000
        self.assertEqual(evaluate("F5", o)["status"], "inconclusive")

    def test_uncertainty_boundary_must_be_strict(self):
        o = telemetry(); o["events"] = [event(1, 10050), event(2, 11050)]
        self.assertEqual(evaluate("F5", o)["status"], "inconclusive")
        o["events"][0]["sampled_at_device"] += 1
        o["events"][0]["elapsed_realtime_ms"] += 1
        self.assertEqual(evaluate("F5", o)["status"], "confirmed")

    def test_server_device_offset_applied(self):
        o = telemetry(); o["events"] = [event(1, 8000), event(2, 9000)]
        for e in o["events"]:
            e["clock_offset_ms"] = 5000; e["received_at_server"] += 5000
        self.assertEqual(evaluate("F5", o)["status"], "confirmed")

    def test_network_retries_do_not_count_twice(self):
        o = telemetry(); e = event(1); retry = copy.deepcopy(e); retry["received_at_server"] += 500
        o["events"] = [e, retry]
        self.assertEqual(evaluate("F5", o)["status"], "inconclusive")

    def test_arrival_order_does_not_change_result(self):
        o = telemetry(); o["events"].reverse()
        self.assertEqual(evaluate("F5", o)["status"], "confirmed")

    def test_conflicting_sequence_is_excluded(self):
        o = telemetry(); collision = copy.deepcopy(o["events"][0]); collision["a11y_enabled"] = False
        o["events"].append(collision)
        self.assertEqual(evaluate("F5", o)["status"], "inconclusive")

    def test_instances_cannot_be_mixed(self):
        o = telemetry(); o["events"][1]["instance_id"] = "another"
        self.assertEqual(evaluate("F5", o)["status"], "inconclusive")

    def test_missing_sync_stale_sync_future_time_or_nan_excluded(self):
        for changes in ({"clock_offset_ms": None}, {"clock_sync_age_ms": 400000},
                        {"clock_uncertainty_ms": 2001}, {"sampled_at_device": float("nan")},
                        {"received_at_server": 1}, {"boot_id": ""}):
            o = telemetry(); o["events"][0].update(changes)
            self.assertEqual(evaluate("F5", o)["status"], "inconclusive")

    def test_wall_clock_jump_does_not_create_survival(self):
        o = telemetry(); o["events"][1]["sampled_at_device"] += 60000
        o["events"][1]["received_at_server"] += 60000
        self.assertEqual(evaluate("F5", o)["status"], "inconclusive")

    def test_fresh_resynchronization_can_correct_wall_clock_jump(self):
        o = telemetry(); o["events"][1]["sampled_at_device"] += 60000
        o["events"][1]["clock_offset_ms"] -= 60000
        o["events"][1]["a11y_sampled_at"] += 60000
        self.assertEqual(evaluate("F5", o)["status"], "confirmed")
        self.assertEqual(evaluate("F7", o)["status"], "confirmed")

    def test_new_boot_segment_is_handled(self):
        o = telemetry(); o["events"][1]["boot_id"] = "boot-2"; o["events"][1]["elapsed_realtime_ms"] = 1000
        self.assertEqual(evaluate("F5", o)["status"], "confirmed")

    def test_same_installation_sequence_cannot_reset_across_boot(self):
        o = telemetry(); o["events"][1]["boot_id"] = "boot-2"; o["events"][1]["sequence"] = 1
        self.assertEqual(evaluate("F5", o)["status"], "inconclusive")

    def test_minimum_cannot_be_lowered_to_one(self):
        o = telemetry(); o["min_fresh_events"] = 1
        self.assertEqual(evaluate("F5", o)["status"], "inconclusive")

    def test_permission_disabled_preserves_f5_positive(self):
        o = telemetry()
        for e in o["events"]: e["a11y_enabled"] = False
        self.assertEqual(evaluate("F5", o)["status"], "confirmed")
        self.assertEqual(evaluate("F7", o)["status"], "not_observed")

    def test_unknown_permission_not_false(self):
        for unknown in (None, "unknown", "false", 0):
            o = telemetry()
            for e in o["events"]: e["a11y_enabled"] = unknown
            self.assertEqual(evaluate("F7", o)["status"], "inconclusive")

    def test_stale_permission_wrong_component_and_regrant_fail(self):
        for changes in ({"a11y_sampled_at": 9000}, {"a11y_component": "other/.Service"}):
            o = telemetry()
            for e in o["events"]: e.update(changes)
            self.assertEqual(evaluate("F7", o)["status"], "inconclusive")
        o = telemetry(); o["reauthorized"] = True
        self.assertEqual(evaluate("F7", o)["status"], "inconclusive")

    def test_scope_boundaries_reported_without_assuming_next_tenant(self):
        o = telemetry(); o.update(cleanup_ready_server_ms=12000, next_session_server_ms=14000)
        r = evaluate("F5", o)["evidence"]
        self.assertTrue(r["observed_after_cleanup"])
        self.assertFalse(r["observed_after_next_session"])


class F6Tests(unittest.TestCase):
    def test_batch_execution_metadata_does_not_prove_residue_or_cleanliness(self):
        o = dict(batch_execution_complete=True,
                 ui_execution_coverage=dict(flow_completed=1, skipped=1, failed_or_manual=0, remaining=0),
                 package_checks=[dict(target="test", package="org.example", installed=True, status="flow_completed",
                                      target_config={"irrelevant": "do not copy full script"}),
                                 dict(target="missing", package="org.absent", installed=False, status="skipped_not_installed")])
        result = evaluate("F6", o)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["evidence"]["ui_execution_coverage"]["skipped"], 1)
        self.assertEqual(result["evidence"]["package_checks"][1]["status"], "skipped_not_installed")
        self.assertNotIn("target_config", result["evidence"]["package_checks"][0])

    def test_file_alone_is_positive_without_ui(self):
        r = evaluate("F6", file_observation())
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["subresults"]["ui_residue"]["status"], "inconclusive")

    def test_unattributed_hit_not_confirmed(self):
        o = file_observation(); o["files"][0]["attributed_to_prior_session"] = None
        self.assertEqual(evaluate("F6", o)["status"], "inconclusive")

    def test_directory_public_file_not_residue(self):
        for changes in ({"kind": "directory"}, {"public_resource": True}):
            o = file_observation(); o["files"][0].update(changes); o["ui_scan_complete"] = True
            self.assertEqual(evaluate("F6", o)["status"], "not_observed")

    def test_ui_alone_can_confirm(self):
        o = dict(files=[], file_scan_complete=True, ui_scan_complete=True,
                 ui=[dict(prior_session_content_visible=True, attributed_to_prior_session=True, evidence_ref="evidence/screen.png")])
        self.assertEqual(evaluate("F6", o)["status"], "confirmed")

    def test_permission_denied_is_unknown(self):
        o = dict(files=[], file_scan_complete=True, ui_scan_complete=True, access_errors=["Permission denied"])
        self.assertEqual(evaluate("F6", o)["status"], "inconclusive")

    def test_complete_negative_scan(self):
        o = dict(files=[], ui=[], file_scan_complete=True, ui_scan_complete=True, access_errors=[])
        self.assertEqual(evaluate("F6", o)["status"], "not_observed")


if __name__ == "__main__":
    unittest.main()
