"""Real local HTTP/SQLite integration; no device or external service is used."""
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from actscope.oracles import evaluate
from actscope.telemetry import CollectorError, CollectorStore, ROOT, handler_for, inside_project, validate_event


class CollectorTests(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / ".test-tmp"
        temporary.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.tmp.cleanup)
        self.store = CollectorStore(self.tmp.name)
        self.token = self.store.initialize("trial")['token']

    def event(self, sequence=1, sample=10000, **kwargs):
        value = dict(run_id="trial", instance_id="instance-1", sequence=sequence,
                     sampled_at_device=sample, build_id="controlled-build",
                     a11y_component="org.actscope.probe/tv.danmaku.bili.ProbeAccessibilityService",
                     a11y_enabled=True, a11y_sampled_at=sample,
                     service_last_heartbeat=None, boot_id="boot-1",
                     elapsed_realtime_ms=sample - 1000, clock_offset_ms=100,
                     clock_uncertainty_ms=10, clock_sync_age_ms=1000)
        value.update(kwargs)
        return value

    def send(self, sequence=1, sample=10000, **kwargs):
        return self.store.ingest(self.token, self.event(sequence, sample, **kwargs), received_at=sample + 200)

    def test_secret_is_hashed_in_database(self):
        with self.store.connect() as db:
            row = db.execute("SELECT token_hash FROM runs").fetchone()
        self.assertNotEqual(row[0], self.token)
        self.assertEqual(len(row[0]), 64)

    def test_authentication_does_not_bind_instance(self):
        with self.assertRaises(CollectorError) as caught:
            self.store.ingest("wrong-token", self.event())
        self.assertEqual(caught.exception.status, 401)
        self.assertIsNone(self.store.export("trial")["expected_instance_id"])
        self.assertFalse(self.store.export("trial")["events"])

    def test_retry_preserves_original_receive_time(self):
        first = self.send()
        second = self.store.ingest(self.token, self.event(), received_at=30000)
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["received_at_server"], second["received_at_server"])
        self.assertEqual(len(self.store.export("trial")["events"]), 1)

    def test_conflicting_retry_rejected_without_rewriting(self):
        self.send()
        with self.assertRaises(CollectorError) as caught:
            self.store.ingest(self.token, self.event(a11y_enabled=False))
        self.assertEqual(caught.exception.status, 409)
        self.assertTrue(self.store.export("trial")["events"][0]["a11y_enabled"])

    def test_different_installation_cannot_mix_into_run(self):
        self.send()
        with self.assertRaises(CollectorError) as caught:
            self.send(2, instance_id="new-installation")
        self.assertEqual(caught.exception.status, 409)

    def test_lifecycle_is_immutable_and_ordered(self):
        self.store.mark("trial", "end", 20000)
        with self.assertRaises(CollectorError):
            self.store.mark("trial", "end", 21000)
        with self.assertRaises(CollectorError):
            self.store.mark("trial", "ready", 19000)
        self.store.mark("trial", "ready", 25000)
        self.assertEqual(self.store.export("trial")["session_end_server_ms"], 20000)

    def populate_valid_run(self):
        self.send(1, 10000)
        self.send(2, 15000)
        self.store.mark("trial", "end", 20000, "platform confirmed returned")
        self.send(3, 25000)
        self.send(4, 30000)

    def test_collector_export_confirms_f5_and_f7_end_to_end(self):
        self.populate_valid_run()
        observation = self.store.export("trial", no_reauthorization=True)
        self.assertTrue(observation["baseline_telemetry_verified"])
        self.assertEqual(evaluate("F5", observation)["status"], "confirmed")
        self.assertEqual(evaluate("F7", observation)["status"], "confirmed")

    def test_no_reauthorization_must_be_explicit(self):
        self.populate_valid_run()
        observation = self.store.export("trial")
        self.assertEqual(evaluate("F5", observation)["status"], "confirmed")
        self.assertEqual(evaluate("F7", observation)["status"], "inconclusive")

    def test_delayed_pre_return_samples_do_not_confirm_residue(self):
        self.send(1, 10000)
        self.send(2, 12000)
        self.store.mark("trial", "end", 20000)
        for sequence, sample in ((3, 14000), (4, 16000)):
            self.store.ingest(self.token, self.event(sequence, sample), received_at=30000)
        self.assertEqual(evaluate("F5", self.store.export("trial"))["status"], "inconclusive")

    def test_no_heartbeat_is_not_negative(self):
        self.store.mark("trial", "end", 20000)
        self.assertEqual(evaluate("F5", self.store.export("trial"))["status"], "inconclusive")

    def test_missing_sync_prevents_baseline(self):
        self.send(1, clock_offset_ms=None)
        self.send(2, 15000, clock_offset_ms=None)
        self.store.mark("trial", "end", 20000)
        self.assertFalse(self.store.export("trial")["baseline_telemetry_verified"])

    def test_unknown_boot_is_stored_without_blocking_later_samples(self):
        self.send(1, boot_id=None)
        self.send(2, 15000)
        self.store.mark("trial", "end", 20000)
        observation = self.store.export("trial")
        self.assertEqual(len(observation["events"]), 2)
        self.assertFalse(observation["baseline_telemetry_verified"])

    def test_post_return_permission_cannot_supply_initial_grant(self):
        self.send(1, 10000, a11y_enabled=False)
        self.send(2, 16000, a11y_sampled_at=20500)
        self.store.mark("trial", "end", 20000)
        self.send(3, 25000)
        self.send(4, 30000)
        observation = self.store.export("trial", no_reauthorization=True)
        self.assertFalse(observation["initial_a11y_enabled"])
        self.assertEqual(evaluate("F7", observation)["status"], "inconclusive")

    def test_validation_rejects_unknown_data_and_nonfinite_clock(self):
        for update in ({"contact_list": []}, {"clock_offset_ms": float("nan")},
                       {"sequence": True}, {"a11y_enabled": True, "a11y_sampled_at": None}):
            with self.subTest(update=update), self.assertRaises(CollectorError):
                validate_event(self.event(**update))

    def test_paths_cannot_escape_project(self):
        with self.assertRaises(CollectorError):
            inside_project(ROOT.parent / "outside-results")
        link = Path(self.tmp.name) / "outside"
        link.symlink_to(ROOT.parent, target_is_directory=True)
        with self.assertRaises(CollectorError):
            inside_project(link / "result.json")

    def test_real_http_auth_and_retry(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(self.store))
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        self.addCleanup(connection.close)
        connection.request("GET", "/v1/time")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertGreater(json.loads(response.read())["server_time_ms"], 0)
        body = json.dumps(self.event())
        connection.request("POST", "/v1/telemetry", body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        self.assertEqual(response.status, 401)
        response.read()
        for duplicate in (False, True):
            connection.request("POST", "/v1/telemetry", body,
                               {"Content-Type": "application/json", "Authorization": "Bearer " + self.token})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["duplicate"], duplicate)
        invalid = body.replace('"clock_offset_ms": 100', '"clock_offset_ms": NaN')
        connection.request("POST", "/v1/telemetry", invalid,
                           {"Content-Type": "application/json", "Authorization": "Bearer " + self.token})
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()


if __name__ == "__main__":
    unittest.main()
