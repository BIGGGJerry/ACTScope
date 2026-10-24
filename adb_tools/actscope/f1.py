"""Low-configuration F1 workflow using the supplied, passive A/B fixtures."""
from __future__ import annotations
import sys
import uuid
from pathlib import Path
from .executor import sha256_file
from .probes import run_probe
from .store import RunStore, project_path, read_json, write_json

MANIFEST_PATH = "artifacts/f1/manifest.json"


def load_fixtures() -> dict:
    manifest = read_json(MANIFEST_PATH)
    if not isinstance(manifest, dict):
        raise ValueError("F1 fixture manifest must be an object")
    verified = {"package_name": manifest.get("package_name")}
    for label in ("A", "B"):
        record = manifest.get(label)
        if not isinstance(record, dict) or not record.get("build_id"):
            raise ValueError(f"F1 manifest lacks {label} identity; rebuild the supplied test fixtures")
        path = project_path(record["path"], must_exist=True)
        digest = sha256_file(path)
        if digest != str(record.get("sha256", "")).lower():
            raise ValueError(f"F1 fixture {label} SHA-256 differs from manifest; rebuild fixtures before testing")
        verified[label] = {**record, "path": str(path), "sha256": digest}
    if verified["A"]["sha256"] == verified["B"]["sha256"] or verified["A"]["build_id"] == verified["B"]["build_id"]:
        raise ValueError("F1 fixtures A and B must have different content and build identities")
    return verified


def begin(store: RunStore, *, duration: float = 120, roots: list[str] | None = None,
          active: bool = False, baseline_verified: bool = False, baseline_evidence: str = "") -> dict:
    if active and not baseline_verified:
        raise ValueError("Active F1 requires --baseline-verified only after A installed normally through the platform")
    if baseline_evidence:
        project_path(baseline_evidence, must_exist=True)
    fixtures = load_fixtures()
    correlation = "owned-upload-" + uuid.uuid4().hex
    snapshot = {"run_id": store.run_id, "controlled_upload_id": correlation,
                "fixtures": fixtures, "baseline": {"verified": baseline_verified,
                "evidence": baseline_evidence, "source": "operator_flag"}}
    write_json(store.path / "f1-fixtures.json", snapshot)
    options = {"original_apk": fixtures["A"]["path"], "replacement_apk": fixtures["B"]["path"],
               "owned_test_artifacts": True, "normal_baseline_verified": baseline_verified,
               "controlled_upload_id": correlation, "roots": roots or ["/"], "duration_s": duration,
               "poll_s": 1, "scan_timeout_s": 30, "max_files": 1000,
               "requested_build_id": fixtures["A"]["build_id"], "replacement_build_id": fixtures["B"]["build_id"],
               "simple_workflow": True}
    store.append("f1_simple_start", {**snapshot, "active": active, "options": options})
    print("F1：正在建立当前 shell 可访问范围内的 APK 基线，请暂时不要发起本轮安装。", file=sys.stderr, flush=True)

    def progress(kind: str, details: dict) -> None:
        if kind == "baseline_complete":
            scope = "；存在访问/扫描限制，详见 evidence.jsonl" if not details.get("complete") else ""
            print(f"F1 基线完成{scope}。请现在通过平台上传 A：{fixtures['A']['path']}", file=sys.stderr, flush=True)
            action = "仅对内容仍匹配本轮 A 的新增/改写 APK 尝试替换 B" if active else "本轮仅扫描，不执行替换"
            print(f"F1：继续监测 {duration:g} 秒；{action}。", file=sys.stderr, flush=True)
        elif kind == "candidate" and details.get("matches_owned_original"):
            state = "已尝试受控替换" if details.get("replacement_attempted") else "只观察到候选"
            print(f"F1：发现本轮 A：{details['path']}；{state}，尚未确认最终安装劫持。", file=sys.stderr, flush=True)

    result = run_probe(store, "F1", options, active, progress=progress)
    print("F1 监测结束。请查看原平台安装任务的最终应用，再使用 f1-finalize 登记实测结果。", file=sys.stderr, flush=True)
    return result


def finalize(store: RunStore, *, task_id: str, installed: str, evidence: str,
             exclude_platform_transform: bool = False) -> dict:
    if installed not in {"A", "B", "unknown"}:
        raise ValueError("installed must be A, B or unknown")
    if not task_id.strip():
        raise ValueError("A non-empty real platform installation task ID is required")
    evidence_path = project_path(evidence, must_exist=True)
    if not evidence_path.is_file() or evidence_path.stat().st_size == 0:
        raise ValueError("Provide a non-empty screenshot/log file supporting the observed original platform task and final app")
    snapshot = read_json(store.path / "f1-fixtures.json")
    observation = read_json(store.path / "observations" / "F1.json")
    if snapshot.get("run_id") != store.run_id or observation.get("controlled_upload_id") != snapshot.get("controlled_upload_id"):
        raise ValueError("Finalization must refer to the latest simple F1 observation in this run")
    if not observation.get("simple_workflow"):
        raise ValueError("Use import-observation for advanced or device-side F1 observations")
    fixtures = snapshot["fixtures"]
    if observation.get("original_sha256") != fixtures["A"]["sha256"] or observation.get("replacement_sha256") != fixtures["B"]["sha256"]:
        raise ValueError("Observed A/B identities differ from the saved fixture snapshot")
    known = installed in {"A", "B"}
    declaration = {"source": "operator_observation", "controlled_upload_id": snapshot["controlled_upload_id"],
                   "original_platform_task_id": task_id, "installed_fixture": installed,
                   "evidence": str(evidence_path), "evidence_sha256": sha256_file(evidence_path),
                   "platform_transform_excluded": exclude_platform_transform,
                   "meaning": "Operator observed this fixture in the original platform installation task, not a separate B installation or copy-command output"}
    store.append("f1_final_observation", declaration)
    observation.update({"original_install_task_id": task_id, "observed_install_task_id": task_id,
                        "install_completed": known, "installed_identity_verified": known,
                        "installed_build_id": fixtures[installed]["build_id"] if known else None,
                        # An observed on-screen marker is a build identity, not a measured installed-file hash.
                        "installed_sha256": None, "legitimate_transform_excluded": exclude_platform_transform,
                        "observation_complete": known and observation.get("active") is True,
                        "final_identity_source": "operator_ui_or_log",
                        "operator_final_observation": declaration})
    if known:
        observation["limitations"] = [text for text in observation.get("limitations", [])
            if text != "Final installation task and installed build must be observed and imported separately."]
    if observation.get("active") is not True:
        observation["limitations"] = [*observation.get("limitations", []),
            "Observation-only mode did not attempt controlled replacement; it cannot establish a completed negative F1 test."]
    return store.save_observation("F1", observation)
