"""Dependency-free command line entry point."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from .adapters import EVENT_TYPES, PlatformAdapter
from .probes import run_probe
from .store import PROJECT_ROOT, RunStore, project_path, read_json

FAILURES = [f"F{i}" for i in range(1, 8)]


def parser() -> argparse.ArgumentParser:
    main = argparse.ArgumentParser(prog="python -m actscope", description="ACTScope controlled experiments and evidence reports (Python 3.10+)")
    sub = main.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create an immutable configuration snapshot and run folder")
    init.add_argument("--config", required=True)
    init.add_argument("--run-id")
    cap = sub.add_parser("capabilities", help="Show configured capabilities and manual platform steps")
    cap.add_argument("--run", required=True)
    event = sub.add_parser("event", help="Record an observed platform lifecycle transition")
    event.add_argument("--run", required=True)
    event.add_argument("--type", required=True, choices=sorted(EVENT_TYPES))
    event.add_argument("--time", help="ISO 8601 timezone-aware observation time; default current server time")
    event.add_argument("--note", required=True)
    event.add_argument("--evidence", default="", help="Path to platform screenshot/log inside project")
    event.add_argument("--device-id", default="")
    deploy = sub.add_parser("deploy", help="Record manual installation or explicitly submit via ADB")
    deploy.add_argument("--run", required=True)
    deploy.add_argument("--apk", required=True)
    deploy.add_argument("--route", default="platform_ui")
    deploy.add_argument("--active", action="store_true", help="Actually install via the selected ADB route")
    probe = sub.add_parser("probe", help="Run a bounded host probe; mutations require --active")
    probe.add_argument("--run", required=True)
    probe.add_argument("--failure", choices=["F1", "F3", "F4", "F6"], required=True)
    probe.add_argument("--options", required=True, help="Path to probe JSON options")
    probe.add_argument("--active", action="store_true", help="Enable controlled APK replacement, dangerous test or UI actions")
    f1 = sub.add_parser("f1", help="Scan for the supplied owned A fixture and optionally replace it with B")
    f1.add_argument("--run", required=True)
    f1.add_argument("--duration", type=float, default=120, help="Monitoring seconds after the scan baseline (default 120)")
    f1.add_argument("--roots", nargs="+", default=["/"], help="Readable Android roots; default /")
    f1.add_argument("--active", action="store_true", help="Replace only new/rewritten APKs matching this run's owned A")
    f1.add_argument("--baseline-verified", action="store_true", help="Operator confirms A was installed normally through the platform before this attempt")
    f1.add_argument("--baseline-evidence", default="", help="Optional screenshot/log of the normal A installation inside this project")
    final = sub.add_parser("f1-finalize", help="Register the fixture actually seen after the original platform installation task")
    final.add_argument("--run", required=True)
    final.add_argument("--task-id", required=True, help="Real original platform installation task ID")
    final.add_argument("--installed", choices=["A", "B", "unknown"], required=True, help="Fixture seen in the original task's final app, never inferred from cp output or separate B installation")
    final.add_argument("--evidence", required=True, help="Project-local screenshot/log showing original task and final app identity")
    final.add_argument("--exclude-platform-transform", action="store_true", help="Operator has excluded legitimate resigning/instrumentation as explanation for the observed replacement build")
    imported = sub.add_parser("import-observation", help="Evaluate documented manual/device observations")
    imported.add_argument("--run", required=True)
    imported.add_argument("--failure", choices=FAILURES, required=True)
    imported.add_argument("--file", required=True)
    imported.add_argument("--merge", action="store_true", help="Recursively merge into latest observation; lists are replaced explicitly")
    imported.add_argument("--note", default="Operator supplied observation; consult attached evidence")
    device = sub.add_parser("import-device-probe", help="Import Android probe bundle F1/F6 evidence without inferring identity or provenance")
    device.add_argument("--run", required=True)
    device.add_argument("--file", required=True)
    device.add_argument("--failure", choices=["F1", "F6"], required=True)
    report = sub.add_parser("report", help="Write JSON, CSV and Markdown summary from latest results")
    report.add_argument("--run", required=True)
    return main


def deep_merge(old: dict, new: dict) -> dict:
    result = dict(old)
    for key, value in new.items():
        result[key] = deep_merge(result[key], value) if isinstance(value, dict) and isinstance(result.get(key), dict) else value
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "init":
            config = read_json(arguments.config)
            if not isinstance(config, dict) or not config.get("platform"):
                raise ValueError("Configuration must be an object with a platform name")
            store = RunStore.create(config, arguments.run_id)
            output = {"run_id": store.run_id, "path": str(store.path), "next": "Verify capabilities and record session_started before collecting evidence"}
        else:
            store = RunStore(arguments.run)
            adapter = PlatformAdapter(store)
            if arguments.command == "capabilities":
                output = adapter.capabilities()
            elif arguments.command == "event":
                output = adapter.record_event(arguments.type, time=arguments.time, note=arguments.note,
                                              evidence=arguments.evidence, device_id=arguments.device_id)
            elif arguments.command == "deploy":
                output = adapter.deploy_app(arguments.apk, arguments.route, active=arguments.active)
            elif arguments.command == "f1":
                from .f1 import begin
                output = begin(store, duration=arguments.duration, roots=arguments.roots, active=arguments.active,
                               baseline_verified=arguments.baseline_verified, baseline_evidence=arguments.baseline_evidence)
            elif arguments.command == "f1-finalize":
                from .f1 import finalize
                output = finalize(store, task_id=arguments.task_id, installed=arguments.installed,
                                  evidence=arguments.evidence, exclude_platform_transform=arguments.exclude_platform_transform)
            elif arguments.command == "probe":
                options = read_json(arguments.options)
                if not isinstance(options, dict):
                    raise ValueError("Probe options must be a JSON object")
                output = run_probe(store, arguments.failure, options, arguments.active)
            elif arguments.command == "import-device-probe":
                source_path = project_path(arguments.file, must_exist=True)
                # Parse, hash and archive exactly the same bytes, even if the source changes later.
                bundle_bytes = source_path.read_bytes()
                bundle = json.loads(bundle_bytes)
                if not isinstance(bundle, dict) or bundle.get("schema") != "actscope.device.bundle.v1":
                    raise ValueError("Expected actscope.device.bundle.v1 bundle")
                if bundle.get("run_id") != store.run_id:
                    raise ValueError("Device bundle run_id differs from this experiment")
                key = "f1_result" if arguments.failure == "F1" else "f6_result"
                observation = bundle.get(key)
                if not isinstance(observation, dict):
                    raise ValueError(f"Bundle contains no {key}")
                for identity_key in ("run_id", "instance_id", "build_id"):
                    inner = observation.get(identity_key)
                    outer = bundle.get(identity_key)
                    if not isinstance(inner, str) or not inner.strip() or not isinstance(outer, str) or not outer.strip():
                        raise ValueError(f"Device bundle and {key} must both contain non-empty {identity_key}")
                    if inner != outer:
                        raise ValueError(f"Device {key} {identity_key} differs from bundle; retained evidence cannot be relabelled")
                bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
                archive_path = project_path(store.path / "evidence" / "device-bundles" / f"{bundle_sha256}.json")
                if not archive_path.is_relative_to(store.path):
                    raise ValueError("Archived device bundle must remain inside the current run")
                archive_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive_path.open("xb") as archive:
                        archive.write(bundle_bytes)
                except FileExistsError:
                    if archive_path.read_bytes() != bundle_bytes:
                        raise ValueError("Existing content-addressed bundle is corrupted; refusing to overwrite evidence")
                store.append("device_bundle_import", {"source_file": str(source_path),
                            "bundle_evidence_path": archive_path.relative_to(store.path).as_posix(),
                            "bundle_sha256": bundle_sha256, "bundle_bytes": len(bundle_bytes),
                            "instance_id": bundle.get("instance_id"), "build_id": bundle.get("build_id"),
                            "failure_mode": arguments.failure, "ui_trace": bundle.get("ui_trace"),
                            "source": "device_export_imported_by_operator"})
                output = store.save_observation(arguments.failure, observation)
            elif arguments.command == "import-observation":
                observation = read_json(arguments.file)
                if not isinstance(observation, dict):
                    raise ValueError("Observation must be a JSON object")
                raw_imported_observation = observation
                # Telemetry exporter may return separate F5/F7 keys in one bundle.
                if arguments.failure in observation and isinstance(observation[arguments.failure], dict):
                    observation = observation[arguments.failure]
                if arguments.merge:
                    existing_path = store.path / "observations" / f"{arguments.failure}.json"
                    existing = read_json(existing_path) if existing_path.exists() else {}
                    observation = deep_merge(existing, observation)
                synthetic = isinstance(observation.get("_example"), dict) and observation["_example"].get("synthetic") is True
                if not synthetic:
                    for identity_key in ("expected_run_id", "run_id"):
                        if identity_key in observation and observation[identity_key] != store.run_id:
                            raise ValueError(f"Observation {identity_key} differs from this experiment; evidence cannot be relabelled")
                store.append("observation_import", {"failure_mode": arguments.failure, "source_file": str(project_path(arguments.file)),
                                                   "source": "operator_import", "merge": arguments.merge, "note": arguments.note,
                                                   "raw_imported_observation": raw_imported_observation})
                output = store.save_observation(arguments.failure, observation)
            else:
                output = store.report()
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, KeyError, OSError, RuntimeError) as error:
        print(f"ACTScope: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ACTScope interrupted; inspect evidence and pending proxy restoration state before resuming.", file=sys.stderr)
        return 130
