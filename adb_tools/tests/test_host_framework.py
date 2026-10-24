import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from actscope import cli
from actscope.adapters import PlatformAdapter
from actscope.executor import AdbExecutor, CommandResult
from actscope.probes import probe_f1, probe_f3, probe_f4, probe_f6
from actscope.rules import parse_rules
from actscope.store import PROJECT_ROOT, RunStore, project_path, write_json


class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp_root = PROJECT_ROOT / '.test-tmp'
        self.tmp_root.mkdir(exist_ok=True)
        self.temp = Path(tempfile.mkdtemp(dir=self.tmp_root))
        self.store_path = self.temp / 'run'
        self.store_path.mkdir()
        write_json(self.store_path / 'run.json', {'run_id': 'test-run', 'config': {'platform': 'mock', 'capabilities': {'remote_adb': True, 'install_routes': ['platform_ui', 'adb']}, 'adb': {'serial': 'mock-device'}}})
        self.store = RunStore(self.store_path)
        self.executor = AdbExecutor('mock-device', self.store)

    def tearDown(self):
        shutil.rmtree(self.temp)

    def result(self, args, stdout='', returncode=0, stderr=''):
        return CommandResult(['adb', '-s', 'mock-device', *args], '2000-01-01T12:00:01+00:00', 0, returncode, stdout, stderr)

    def test_paths_cannot_escape_with_dotdot_or_symlink(self):
        with self.assertRaises(ValueError):
            project_path('../outside')
        link = self.temp / 'outside'
        link.symlink_to(PROJECT_ROOT.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            project_path(link / 'outside.json')

    def test_subprocess_uses_serial_no_host_shell_and_records_timeout(self):
        with patch('actscope.executor.subprocess.run', side_effect=subprocess.TimeoutExpired(['adb'], 1, b'partial', b'blocked')) as run:
            result = self.executor.shell_args(['stat', '/sdcard/a; rm anything'])
        self.assertTrue(result.timed_out)
        self.assertEqual(run.call_args.args[0][:3], ['adb', '-s', 'mock-device'])
        self.assertFalse(run.call_args.kwargs['shell'])
        self.assertIn("'/sdcard/a; rm anything'", run.call_args.args[0][-1])
        self.assertEqual(self.store.read_events()[-1]['kind'], 'command')

    def test_actual_legacy_rules_keep_dots_spaces_and_terminal_file(self):
        rules = parse_rules(PROJECT_ROOT / 'rules/qq.txt')
        self.assertTrue(any(r.path.endswith('/.AppCenterWebBuffer_QQ') for r in rules))
        self.assertTrue(any(r.path.endswith('/photo/ ') for r in rules))
        self.assertTrue(any(r.kind == 'file' and r.path.endswith('/wifi') for r in rules))
        for rule_path in (PROJECT_ROOT / 'rules').glob('*.txt'):
            self.assertTrue(parse_rules(rule_path))

    def test_f1_only_replaces_new_or_rewritten_matching_owned_hash(self):
        original = self.temp / 'a.apk'; original.write_bytes(b'A')
        replacement = self.temp / 'b.apk'; replacement.write_bytes(b'B')
        import hashlib
        a_hash, other_hash = hashlib.sha256(b'A').hexdigest(), hashlib.sha256(b'other').hexdigest()
        scans = [({'/data/local/tmp/reused.apk': other_hash}, [], True),
                 ({'/data/local/tmp/reused.apk': a_hash, '/data/local/tmp/unrelated.apk': other_hash}, [], True)]
        options = {'original_apk': str(original), 'replacement_apk': str(replacement), 'owned_test_artifacts': True,
                   'original_install_task_id': 'owned-task', 'duration_s': 0.1, 'poll_s': 0.1}
        commands = []
        def execute(args, **kw):
            commands.append(args)
            return self.result(args, 'ok')
        with patch('actscope.probes.scan_apks', side_effect=scans), patch.object(self.executor, 'run', side_effect=execute):
            observation = probe_f1(self.store, self.executor, options, True)
        copy_commands = [c[-1] for c in commands if c[0] == 'shell' and 'cp ' in c[-1]]
        self.assertEqual(len(copy_commands), 1)
        self.assertIn('reused.apk', copy_commands[0])
        self.assertNotIn('unrelated.apk', copy_commands[0])
        self.assertIn(a_hash, copy_commands[0])
        self.assertTrue(observation['replacement_attempted'])
        self.assertFalse(observation['install_completed'])
        self.assertTrue(any('rm -f' in c[-1] for c in commands))

    def test_f1_dry_run_never_pushes_or_replaces(self):
        original = self.temp / 'a.apk'; original.write_bytes(b'A')
        replacement = self.temp / 'b.apk'; replacement.write_bytes(b'B')
        options = {'original_apk': str(original), 'replacement_apk': str(replacement), 'duration_s': 0.1, 'poll_s': 0.1}
        with patch('actscope.probes.scan_apks', return_value=({}, [], True)), patch.object(self.executor, 'run') as run:
            observation = probe_f1(self.store, self.executor, options, False)
        run.assert_not_called()
        self.assertFalse(observation['replacement_attempted'])

    def test_f4_fresh_echo_on_old_serial_confirms_without_connect(self):
        from actscope.oracles import evaluate
        def execute(args, **kw):
            import shlex
            command = shlex.split(args[-1])
            return self.result(args, command[-1])
        with patch.object(self.executor, 'run', side_effect=execute) as run:
            probe_f4(self.store, self.executor, {'phase': 'baseline'})
            baseline_path = self.store.path / 'f4_baseline.json'
            baseline = json.loads(baseline_path.read_text()); baseline['issued_at_server_ms'] = 1
            write_json(baseline_path, baseline)
            PlatformAdapter(self.store).record_event('session_ended', time='2000-01-01T12:00:00Z', note='mock platform confirmed return')
            observation = probe_f4(self.store, self.executor, {'phase': 'post', 'old_authorization_confirmed': True})
        self.assertEqual(evaluate('F4', observation)['status'], 'confirmed')
        self.assertTrue(all(call.args[0][0] == 'shell' for call in run.call_args_list))

    def test_f4_reacquired_session_rejected(self):
        write_json(self.store.path / 'f4_baseline.json', {'serial': 'mock-device', 'success': True})
        self.store.append('session_ended', {'time': '2000-01-01T12:00:00Z'})
        with patch('actscope.store.utc_now', return_value='2099-01-01T00:00:00Z'):
            self.store.append('session_reacquired', {})
        with self.assertRaises(ValueError):
            probe_f4(self.store, self.executor, {'phase': 'post', 'old_authorization_confirmed': True})

    def test_f3_inactive_does_not_execute(self):
        with patch.object(self.executor, 'run') as run:
            observation = probe_f3(self.store, self.executor, {'case': 'reboot'}, False)
        run.assert_not_called()
        self.assertEqual(observation['cases'], [])

    def test_proxy_restores_absent_setting_in_finally(self):
        import shlex
        calls = []
        def execute(args, **kwargs):
            calls.append(args[-1])
            command = shlex.split(args[-1])
            if command[0] == 'printf':
                return self.result(args, command[-1])
            if command[:3] == ['settings', 'list', 'global']:
                return self.result(args, 'unrelated=1\n')
            if command[:3] == ['settings', 'get', 'global']:
                raise RuntimeError('mock interrupted observation')
            return self.result(args)
        with patch.object(self.executor, 'run', side_effect=execute):
            with self.assertRaises(RuntimeError):
                probe_f3(self.store, self.executor, {'case': 'http_proxy', 'proxy': '127.0.0.1:18080', 'controlled_endpoint': True, 'recovery_plan': 'mock independent recovery'}, True)
        self.assertIn('settings delete global http_proxy', calls)
        self.assertFalse(json.loads((self.store.path / 'f3_proxy_snapshot.json').read_text())['pending_restore'])

    def test_f6_permission_denied_never_becomes_absence(self):
        rule = self.temp / 'sample.txt'; rule.write_text('FOLDER.private/FILE.test\n')
        with patch.object(self.executor, 'run', return_value=self.result([], '', 1, 'Permission denied')):
            observation = probe_f6(self.store, self.executor, {'rules': [str(rule)]})
        self.assertFalse(observation['file_scan_complete'])
        self.assertEqual(observation['files'], [])
        self.assertEqual(observation['access_errors'][0]['error'], 'permission_denied')

    def test_report_and_import_bundle_are_evidence_first(self):
        bundle = self.temp / 'device.json'
        write_json(bundle, {'schema': 'actscope.device.bundle.v1', 'run_id': 'test-run', 'instance_id': 'instance-one', 'build_id': 'build-one', 'f6_result': {'run_id': 'test-run', 'instance_id': 'instance-one', 'build_id': 'build-one', 'files': [], 'file_scan_complete': False}, 'ui_trace': {'completed': True, 'residue_verified': False}})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['import-device-probe', '--run', str(self.store.path), '--file', str(bundle), '--failure', 'F6']), 0)
        report = self.store.report()
        self.assertEqual(report['results'][0]['status'], 'inconclusive')
        self.assertTrue((self.store.path / 'report.csv').exists())
        self.assertTrue((self.store.path / 'report.md').exists())
        self.assertEqual(self.store.read_events()[0]['kind'], 'device_bundle_import')

    def test_no_remote_adb_only_disables_host_method_for_f1_f6(self):
        from actscope.probes import run_probe
        manifest = json.loads((self.store.path / 'run.json').read_text())
        manifest['config']['capabilities']['remote_adb'] = False
        write_json(self.store.path / 'run.json', manifest)
        self.store = RunStore(self.store.path)
        for failure in ['F1', 'F6']:
            result = run_probe(self.store, failure, {}, False)
            self.assertEqual(result['status'], 'inconclusive')
            self.assertEqual(result['method_results'][0]['status'], 'not_applicable')
        self.assertEqual(run_probe(self.store, 'F4', {}, False)['status'], 'not_applicable')

    def test_cli_subprocess_synthetic_import_report_without_adb(self):
        fixture = PROJECT_ROOT / 'configs/observations/f4.confirmed.synthetic.json'
        imported = subprocess.run([sys.executable, '-m', 'actscope', 'import-observation', '--run', str(self.store.path),
                                   '--failure', 'F4', '--file', str(fixture)], cwd=PROJECT_ROOT,
                                  capture_output=True, text=True, timeout=20)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        result = json.loads(imported.stdout)
        self.assertEqual(result['status'], 'confirmed')
        self.assertTrue(result['synthetic'])
        reported = subprocess.run([sys.executable, '-m', 'actscope', 'report', '--run', str(self.store.path)],
                                  cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(reported.returncode, 0, reported.stderr)
        self.assertTrue(json.loads(reported.stdout)['contains_synthetic_examples'])
        self.assertIn('不是任何平台的实测结果', (self.store.path / 'report.md').read_text())
        self.assertFalse(any(event['kind'] == 'command' for event in self.store.read_events()))

    def test_device_bundle_rejects_mismatched_or_missing_inner_identity(self):
        source = self.temp / 'device.json'
        for field in ['run_id', 'instance_id', 'build_id']:
            for missing in [True, False]:
                with self.subTest(field=field, missing=missing):
                    bundle = {'schema': 'actscope.device.bundle.v1', 'run_id': 'test-run', 'instance_id': 'instance-one',
                              'build_id': 'build-one', 'f6_result': {'run_id': 'test-run', 'instance_id': 'instance-one',
                              'build_id': 'build-one', 'files': [], 'file_scan_complete': False}}
                    if missing:
                        bundle['f6_result'].pop(field)
                    else:
                        bundle['f6_result'][field] = 'older-experiment'
                    write_json(source, bundle)
                    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(cli.main(['import-device-probe', '--run', str(self.store.path), '--file', str(source), '--failure', 'F6']), 2)
        self.assertEqual(self.store.read_events(), [])
        self.assertFalse((self.store.path / 'evidence/device-bundles').exists())

    def test_imported_device_bundle_survives_source_removal_byte_for_byte(self):
        import hashlib
        source = self.temp / 'outside-run-bundle.json'
        bundle = {'schema': 'actscope.device.bundle.v1', 'run_id': 'test-run', 'instance_id': 'instance-one',
                  'build_id': 'build-one', 'f6_result': {'run_id': 'test-run', 'instance_id': 'instance-one',
                  'build_id': 'build-one', 'files': [], 'file_scan_complete': False},
                  'ui_evidence': [{'evidence_ref': 'visible-state-01', 'content': {'nodes': [{'text': 'owned test content'}]}}],
                  'ui_evidence_export': {'bytes': 123, 'omitted_count': 2, 'truncated': True, 'diagnostics': ['limit reached']}}
        original = (json.dumps(bundle, indent=4) + '\n\n').encode()
        source.write_bytes(original)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['import-device-probe', '--run', str(self.store.path), '--file', str(source), '--failure', 'F6']), 0)
        imported = self.store.latest_event('device_bundle_import')['data']
        saved = self.store.path / imported['bundle_evidence_path']
        self.assertEqual(imported['source_file'], str(source))
        self.assertEqual(imported['bundle_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(saved.name, imported['bundle_sha256'] + '.json')
        source.unlink()
        self.assertEqual(saved.read_bytes(), original)
        self.assertEqual(json.loads(saved.read_bytes())['ui_evidence_export']['omitted_count'], 2)
        # Importing the same bytes from another path reuses the immutable content object.
        second = self.temp / 'second-export.json'; second.write_bytes(original)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['import-device-probe', '--run', str(self.store.path), '--file', str(second), '--failure', 'F6']), 0)
        self.assertEqual(list(saved.parent.glob('*.json')), [saved])
        self.assertEqual(self.store.latest_event('device_bundle_import')['data']['bundle_evidence_path'], imported['bundle_evidence_path'])

    def test_invalid_device_bundle_schema_never_archives_source(self):
        source = self.temp / 'invalid-bundle.json'
        write_json(source, {'schema': 'unexpected-device-format', 'run_id': 'test-run', 'ui_evidence': ['must not import']})
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['import-device-probe', '--run', str(self.store.path), '--file', str(source), '--failure', 'F6']), 2)
        self.assertFalse((self.store.path / 'evidence/device-bundles').exists())
        self.assertEqual(self.store.read_events(), [])

    def test_reboot_does_not_treat_old_boot_response_as_recovery(self):
        from actscope.oracles import evaluate
        clock = [0.0]
        old = {'source': 'kernel_boot_id', 'value': 'old-boot'}
        with patch.object(self.executor, 'run', return_value=self.result([], '1')):
            with patch('actscope.probes._nonce_response', return_value=('challenge', self.result([], 'challenge'), True)), \
                 patch('actscope.probes.boot_identity', return_value=old), \
                 patch('actscope.probes.time.monotonic', side_effect=lambda: clock[0]), \
                 patch('actscope.probes.time.sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
                observation = probe_f3(self.store, self.executor, {'case': 'reboot', 'duration_s': 3, 'poll_s': 1, 'recovery_plan': 'mock recovery'}, True)
        case = observation['cases'][0]
        self.assertEqual(len(case['checks']), 3)
        self.assertFalse(case['device_recovered'])
        self.assertFalse(case['device_unavailable'])
        self.assertFalse(case['observation_complete'])
        self.assertEqual(evaluate('F3', observation)['status'], 'inconclusive')

    def test_reboot_confirms_recovery_only_after_new_boot_response(self):
        from actscope.oracles import evaluate
        clock = [0.0]
        old = {'source': 'kernel_boot_id', 'value': 'old-boot'}
        new = {'source': 'kernel_boot_id', 'value': 'new-boot'}
        with patch.object(self.executor, 'run', return_value=self.result([], '1')):
            with patch('actscope.probes._nonce_response', return_value=('challenge', self.result([], 'challenge'), True)), \
                 patch('actscope.probes.boot_identity', side_effect=[old, old, new]), \
                 patch('actscope.probes.time.monotonic', side_effect=lambda: clock[0]), \
                 patch('actscope.probes.time.sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
                observation = probe_f3(self.store, self.executor, {'case': 'reboot', 'duration_s': 3, 'poll_s': 1, 'recovery_plan': 'mock recovery'}, True)
        case = observation['cases'][0]
        self.assertEqual(len(case['checks']), 2)
        self.assertTrue(case['device_recovered'])
        self.assertTrue(case['checks'][-1]['boot_identity_changed'])
        self.assertEqual(evaluate('F3', observation)['status'], 'not_observed')

    def test_host_apk_discovery_is_case_insensitive(self):
        from actscope.probes import scan_apks
        with patch.object(self.executor, 'shell', return_value=self.result([], '')) as execute:
            scan_apks(self.executor, ['/data/local/tmp'])
        self.assertIn("-iname '*.apk'", execute.call_args.args[0])

    def test_generic_import_rejects_real_cross_run_evidence(self):
        source = self.temp / 'observation.json'
        for key in ['run_id', 'expected_run_id']:
            with self.subTest(key=key):
                write_json(source, {key: 'a-different-experiment', 'events': []})
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(['import-observation', '--run', str(self.store.path), '--file', str(source), '--failure', 'F5']), 2)
        self.assertEqual(self.store.read_events(), [])

    def test_import_records_original_patch_before_merge(self):
        source = self.temp / 'patch.json'
        self.store.save_observation('F6', {'run_id': 'test-run', 'files': [], 'ui': [], 'file_scan_complete': False})
        patch_value = {'ui_scan_complete': True}
        write_json(source, patch_value)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['import-observation', '--run', str(self.store.path), '--file', str(source), '--failure', 'F6', '--merge']), 0)
        event = self.store.latest_event('observation_import')
        self.assertEqual(event['data']['raw_imported_observation'], patch_value)
        self.assertEqual(json.loads((self.store.path / 'observations/F6.json').read_text())['run_id'], 'test-run')

    def test_f1_can_start_before_platform_assigns_install_task_id(self):
        original = self.temp / 'a.apk'; original.write_bytes(b'A')
        replacement = self.temp / 'b.apk'; replacement.write_bytes(b'B')
        options = {'original_apk': str(original), 'replacement_apk': str(replacement), 'owned_test_artifacts': True,
                   'controlled_upload_id': 'planned-owned-upload-01', 'duration_s': 0.1, 'poll_s': 0.1}
        with patch('actscope.probes.scan_apks', return_value=({}, [], True)), \
             patch.object(self.executor, 'run', return_value=self.result([], '')):
            observation = probe_f1(self.store, self.executor, options, True)
        self.assertEqual(observation['controlled_upload_id'], 'planned-owned-upload-01')
        self.assertEqual(observation['original_install_task_id'], '')
        from actscope.oracles import evaluate
        self.assertEqual(evaluate('F1', observation)['status'], 'inconclusive')

    def test_mobile_f1_wait_and_write_evidence_import_without_claiming_installation(self):
        source = self.temp / 'mobile-f1.json'
        cases = [(trigger, state) for trigger in ('next_upload_at_selected_path', 'next_apk_in_selected_directory')
                 for state in ('waiting_for_next_upload', 'succeeded')]
        for trigger, state in cases:
            with self.subTest(state=state, trigger=trigger):
                observation = {'run_id': 'test-run', 'instance_id': 'instance-one', 'build_id': 'mobile-test',
                               'replacement_trigger': trigger, 'replacement_state': state,
                               'original_sha256': None if state == 'waiting_for_next_upload' else 'a' * 64,
                               'replacement_sha256': 'b' * 64, 'normal_baseline_verified': True,
                               'replacement_attempted': state == 'succeeded', 'replacement_write_verified': state == 'succeeded',
                               'install_completed': False, 'installed_identity_verified': False,
                               'pending_replacement': {'state': state, 'path': '/data/local/tmp/xxx.apk',
                                                       'source_apk_path': '/data/local/tmp/xxx.apk', 'directory': '/data/local/tmp', 'recursive': False},
                               'last_attempt': {'path': '/data/local/tmp/yyy.apk'} if state == 'succeeded' else None}
                write_json(source, {'schema': 'actscope.device.bundle.v1', 'run_id': 'test-run',
                                    'instance_id': 'instance-one', 'build_id': 'mobile-test', 'f1_result': observation})
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(['import-device-probe', '--run', str(self.store.path), '--file', str(source), '--failure', 'F1']), 0)
                saved = json.loads((self.store.path / 'observations/F1.json').read_text())
                self.assertEqual(saved['pending_replacement'], observation['pending_replacement'])
                self.assertEqual(saved['replacement_state'], state)
                self.assertEqual(saved['last_attempt'], observation['last_attempt'])
                result = next(r for r in self.store.report()['results'] if r['failure_mode'] == 'F1')
                self.assertEqual(result['status'], 'inconclusive')

if __name__ == '__main__':
    unittest.main()
