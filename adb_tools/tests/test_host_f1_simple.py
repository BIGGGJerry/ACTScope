import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from actscope import cli
from actscope.executor import CommandResult
from actscope.f1 import begin, finalize, load_fixtures
from actscope.store import PROJECT_ROOT, RunStore, read_json, write_json


class SimpleF1Tests(unittest.TestCase):
    def setUp(self):
        temp_root = PROJECT_ROOT / '.test-tmp'
        temp_root.mkdir(exist_ok=True)
        self.temp = Path(tempfile.mkdtemp(dir=temp_root))
        run = self.temp / 'run'; run.mkdir()
        write_json(run / 'run.json', {'run_id': 'f1-simple-test', 'config': {'platform': 'mock', 'capabilities': {'remote_adb': True}, 'adb': {'serial': 'mock-device'}}})
        self.store = RunStore(run)
        self.manifest = self.temp / 'manifest.json'
        manifest = {'package_name': 'org.actscope.f1fixture'}
        for label in ['A', 'B']:
            path = self.temp / (label + '.apk'); path.write_bytes(('owned passive ' + label).encode())
            manifest[label] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                               'build_id': 'ACTSCOPE-F1-' + label, 'version_name': '1.0-' + label}
        write_json(self.manifest, manifest)
        self.hash_a, self.hash_b = manifest['A']['sha256'], manifest['B']['sha256']
        self.evidence = self.temp / 'observed-task.txt'
        self.evidence.write_text('Mock screenshot/log placeholder: original platform task; observed build marker')

    def tearDown(self):
        shutil.rmtree(self.temp)

    def response(self, args, **kwargs):
        return CommandResult(['adb', '-s', 'mock-device', *args], '2026-10-11T12:00:00+00:00', 0, 0,
                             self.hash_b + ' /data/local/tmp/test.apk\n', '')

    def start(self, *, active=True, baseline=True):
        stderr, stdout = io.StringIO(), io.StringIO()
        count = [0]
        def scan(*args, **kwargs):
            count[0] += 1
            if count[0] == 1:
                return {}, [], True
            self.assertIn('基线完成', stderr.getvalue(), 'Upload prompt must be visible before monitoring begins')
            return {'/data/local/tmp/test.apk': {'sha256': self.hash_a, 'stat': '100|time|inode'}}, [], True
        command = ['f1', '--run', str(self.store.path), '--duration', '0.1']
        if active:
            command.append('--active')
        if baseline:
            command.append('--baseline-verified')
        with patch('actscope.f1.MANIFEST_PATH', str(self.manifest)), patch('actscope.probes.scan_apks', side_effect=scan), \
             patch('actscope.executor.AdbExecutor.run', side_effect=self.response), \
             contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            self.assertEqual(cli.main(command), 0)
        return json.loads(stdout.getvalue()), stderr.getvalue()

    def test_scan_prompts_live_then_requires_final_platform_result(self):
        result, progress = self.start()
        self.assertEqual(result['status'], 'inconclusive')
        self.assertIn('请现在通过平台上传 A', progress)
        observation = read_json(self.store.path / 'observations/F1.json')
        self.assertTrue(observation['replacement_attempted'])
        self.assertTrue(observation['controlled_upload_id'].startswith('owned-upload-'))
        self.assertEqual(observation['requested_build_id'], 'ACTSCOPE-F1-A')
        self.assertFalse(observation['install_completed'])
        self.assertTrue(read_json(self.store.path / 'f1-fixtures.json')['baseline']['verified'])

    def test_active_requires_operator_baseline_without_executing_adb(self):
        with patch('actscope.executor.AdbExecutor.run') as run:
            with self.assertRaisesRegex(ValueError, 'baseline-verified'):
                begin(self.store, active=True)
        run.assert_not_called()
        self.assertFalse((self.store.path / 'f1-fixtures.json').exists())

    def test_fixture_manifest_hash_is_validated_before_measurement(self):
        manifest = read_json(self.manifest)
        Path(manifest['A']['path']).write_bytes(b'changed or replaced artifact')
        with patch('actscope.f1.MANIFEST_PATH', str(self.manifest)):
            with self.assertRaisesRegex(ValueError, 'differs from manifest'):
                load_fixtures()

    def test_finalize_b_uses_observed_build_identity_not_source_digest(self):
        self.start()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(['f1-finalize', '--run', str(self.store.path), '--task-id', 'actual-platform-task', '--installed', 'B',
                             '--evidence', str(self.evidence), '--exclude-platform-transform'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'confirmed')
        observation = read_json(self.store.path / 'observations/F1.json')
        self.assertIsNone(observation['installed_sha256'])
        self.assertEqual(observation['installed_build_id'], 'ACTSCOPE-F1-B')
        self.assertEqual(observation['operator_final_observation']['source'], 'operator_observation')
        self.assertEqual(observation['original_install_task_id'], 'actual-platform-task')
        self.assertEqual(observation['observed_install_task_id'], 'actual-platform-task')

    def test_finalize_b_without_transform_exclusion_is_inconclusive(self):
        self.start()
        result = finalize(self.store, task_id='actual-platform-task', installed='B', evidence=str(self.evidence))
        self.assertEqual(result['status'], 'inconclusive')

    def test_finalize_a_supports_scoped_negative_without_inventing_digest(self):
        self.start()
        result = finalize(self.store, task_id='actual-platform-task', installed='A', evidence=str(self.evidence))
        self.assertEqual(result['status'], 'not_observed')
        self.assertIsNone(read_json(self.store.path / 'observations/F1.json')['installed_sha256'])

    def test_dry_run_never_confirms_replacement_from_operator_label_alone(self):
        self.start(active=False, baseline=False)
        result = finalize(self.store, task_id='actual-platform-task', installed='B', evidence=str(self.evidence), exclude_platform_transform=True)
        self.assertEqual(result['status'], 'inconclusive')
        self.assertFalse(read_json(self.store.path / 'observations/F1.json')['normal_baseline_verified'])

    def test_dry_run_original_a_is_not_a_completed_negative_experiment(self):
        self.start(active=False, baseline=True)
        result = finalize(self.store, task_id='actual-platform-task', installed='A', evidence=str(self.evidence))
        self.assertEqual(result['status'], 'inconclusive')
        self.assertFalse(read_json(self.store.path / 'observations/F1.json')['observation_complete'])

    def test_finalize_unknown_empty_evidence_and_wrong_scan_identity(self):
        self.start()
        result = finalize(self.store, task_id='actual-platform-task', installed='unknown', evidence=str(self.evidence))
        self.assertEqual(result['status'], 'inconclusive')
        self.evidence.write_text('')
        with self.assertRaises(ValueError):
            finalize(self.store, task_id='actual-platform-task', installed='B', evidence=str(self.evidence))
        self.evidence.write_text('observed original platform task')
        observation = read_json(self.store.path / 'observations/F1.json'); observation['controlled_upload_id'] = 'other-attempt'
        write_json(self.store.path / 'observations/F1.json', observation)
        with self.assertRaisesRegex(ValueError, 'latest simple F1'):
            finalize(self.store, task_id='actual-platform-task', installed='B', evidence=str(self.evidence))


if __name__ == '__main__':
    unittest.main()
