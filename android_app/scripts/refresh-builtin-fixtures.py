"""Bundle passive replacement B only; the tester supplies the original APK."""
from pathlib import Path
import hashlib
import json

base = Path(__file__).resolve().parents[1]
source = base.parent / 'adb_tools' / 'artifacts' / 'f1'
target = base / 'app' / 'src' / 'main' / 'assets' / 'f1'
manifest = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
if manifest.get('package_name') != 'org.actscope.f1fixture':
    raise SystemExit('Unexpected F1 fixture package')
bundled = {'package_name': manifest['package_name'], 'purpose': manifest['purpose']}
outputs = {}
for role in ('B',):
    name = f'actscope-f1-{role}.apk'
    data = (source / name).read_bytes()
    if not 0 < len(data) <= 65536 or hashlib.sha256(data).hexdigest() != manifest[role]['sha256']:
        raise SystemExit(f'Invalid published F1 fixture {role}')
    outputs[name] = data
    bundled[role] = {**manifest[role], 'path': name, 'size_bytes': len(data)}
outputs['manifest.json'] = (json.dumps(bundled, indent=2) + '\n').encode('utf-8')
target.mkdir(parents=True, exist_ok=True)
old_a = target / 'actscope-f1-A.apk'
if old_a.is_file():
    old_a.unlink()
for name, data in outputs.items():
    file = target / name
    if not file.is_file() or file.read_bytes() != data:
        file.write_bytes(data)
