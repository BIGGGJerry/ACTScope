"""Publish the two passive fixtures and their exact identities for the F1 CLI."""
import hashlib
import json
from pathlib import Path
import shutil

base = Path(__file__).resolve().parent
project = base.parents[1] / 'adb_tools'
output = project / 'artifacts' / 'f1'
sources = {role: base / 'app' / 'build' / 'outputs' / 'apk' / flavor / 'debug' /
           f'app-{flavor}-debug.apk' for role, flavor in [('A', 'original'), ('B', 'replacement')]}
if not all(path.is_file() for path in sources.values()):
    raise SystemExit('Both fixture APKs must be built before publishing the pair.')
output.mkdir(parents=True, exist_ok=True)
manifest = {'package_name': 'org.actscope.f1fixture', 'purpose': 'passive_owned_f1_fixtures'}
for role, source in sources.items():
    target = output / f'actscope-f1-{role}.apk'
    shutil.copyfile(source, target)
    manifest[role] = {'path': str(target.relative_to(project)),
                      'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                      'build_id': f'ACTSCOPE-F1-{role}', 'version_name': f'1.0-{role}'}
if manifest['A']['sha256'] == manifest['B']['sha256']:
    raise SystemExit('A and B must be distinct builds.')
(output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('Published the A/B test APKs and identity manifest to artifacts/f1/.')
