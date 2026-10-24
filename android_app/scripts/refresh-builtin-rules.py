#!/usr/bin/env python3
"""Regenerate APK assets from the existing ACTScope rules, without editing inputs."""
import hashlib
import json
from pathlib import Path

app_root = Path(__file__).resolve().parents[1]
repo = app_root.parent / 'adb_tools'
assets = app_root / 'app/src/main/assets/f6'
selected = json.loads((repo / 'configs/f6.example.json').read_text())['rules']
records = []
for source in selected:
    path = repo / source
    for number, line in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.split('/')
        components = []
        kind = 'directory'
        for index, part in enumerate(parts):
            if part.startswith('FOLDER.'):
                component = part[7:]
            elif part.startswith('FILE.') and index == len(parts) - 1:
                component, kind = part[5:], 'file'
            else:
                raise ValueError(f'{source}:{number}: unsupported rule')
            if component in ('', '.', '..') or '\0' in component:
                raise ValueError('Invalid path component')
            components.append(component)
        records.append(dict(path='/sdcard/' + '/'.join(components), kind=kind, app=path.stem, source=source, line=number))
file_config = dict(roots=list(dict.fromkeys(r['path'] for r in records)), rule_manifest=records,
                   rule_count=len(records), max_scan_entries=50000, max_results=500, hash_files=False)
(assets / 'file_rules.json').write_text(json.dumps(file_config, ensure_ascii=False, indent=2) + '\n')
names = ['qq','uc','quark','weibo','autonavi','xhs','qqbrowser','baidu','cloudmusic','mi_browser']
packages = ['com.tencent.mobileqq','com.UCMobile','com.quark.browser','com.sina.weibo','com.autonavi.minimap','com.xingin.xhs','com.tencent.mtt','com.baidu.searchbox','com.netease.cloudmusic']
targets = []
for index, name in enumerate(names):
    source = repo / 'droidbot/script' / (name + '.json')
    raw = source.read_bytes()
    script = json.loads(raw)
    (assets / 'ui' / source.name).write_bytes(raw)
    candidate = [{'package': packages[index]}] if index < 9 else [
        {'package': 'com.android.browser', 'manufacturer_guard': ['xiaomi', 'redmi'], 'identity_note': 'Shared with AOSP; require Xiaomi/Redmi device AND original UI state match'},
        {'package': 'com.mi.globalbrowser', 'identity_source': 'https://play.google.com/store/apps/details?id=com.mi.globalbrowser'}]
    blocked = {'welcome_button': 'consent_requires_manual_action'}
    if name == 'qq':
        blocked.update({x: 'login_or_consent_requires_manual_action' for x in ['check_box','protocol_agree','login_button1','login_button2']})
    targets.append(dict(name=name, packages=candidate, script_asset='f6/ui/' + source.name,
                        source='droidbot/script/' + source.name, source_sha256=hashlib.sha256(raw).hexdigest(),
                        state_order=list(script['main']), blocked_views=blocked,
                        interval_ms=7000 if name in ('qqbrowser','weibo') else 1200,
                        app_timeout_ms=120000, step_timeout_ms=12000, max_actions=40))
(assets / 'catalog.json').write_text(json.dumps(dict(schema='actscope.builtin.f6.v1', file_rule_count=len(records), targets=targets), ensure_ascii=False, indent=2) + '\n')
print(f'Embedded {len(records)} file rules and {len(targets)} original UI scripts; inputs unchanged.')
