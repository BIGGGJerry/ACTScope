"""Bounded local storage. No output may escape the adb_tools workspace."""
from __future__ import annotations
import csv
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def project_path(value: str | Path, *, must_exist: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    path = path.resolve()
    if not path.is_relative_to(PROJECT_ROOT):
        raise ValueError(f"Path must be inside {PROJECT_ROOT}: {path}")
    if must_exist and not path.exists():
        raise ValueError(f"Path does not exist: {path}")
    return path


def read_json(path: str | Path) -> Any:
    return json.loads(project_path(path, must_exist=True).read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path = project_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


class RunStore:
    def __init__(self, path: str | Path):
        self.path = project_path(path, must_exist=True)
        self.manifest = read_json(self.path / "run.json")
        self.run_id = self.manifest["run_id"]

    @classmethod
    def create(cls, config: dict, run_id: str | None = None) -> "RunStore":
        run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", run_id):
            raise ValueError("run_id must be 1–96 ASCII letters, digits, dots, underscores or hyphens")
        path = project_path(Path("runs") / run_id)
        path.mkdir(parents=True, exist_ok=False)
        write_json(path / "run.json", {"schema_version": 1, "run_id": run_id,
                   "created_at": utc_now(), "config": config})
        store = cls(path)
        store.append("run_created", {"config": config})
        return store

    def append(self, kind: str, data: dict) -> dict:
        event = {"schema_version": 1, "event_id": uuid.uuid4().hex, "run_id": self.run_id,
                 "recorded_at": utc_now(), "kind": kind, "data": data}
        with (self.path / "evidence.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def read_events(self) -> list[dict]:
        path = self.path / "evidence.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []

    def latest_event(self, kind: str) -> dict | None:
        return next((e for e in reversed(self.read_events()) if e["kind"] == kind), None)

    def save_observation(self, failure_mode: str, observation: dict) -> dict:
        from .oracles import evaluate
        failure_mode = failure_mode.upper()
        if failure_mode not in {"F1", "F2", "F3", "F4", "F5", "F6", "F7"}:
            raise ValueError("Unknown failure mode")
        event = self.append("observation", {"failure_mode": failure_mode, "observation": observation})
        result = evaluate(failure_mode, observation)
        if isinstance(observation.get("method_results"), list):
            result["method_results"] = observation["method_results"]
        if isinstance(observation.get("limitations"), list):
            result["limitations"] = list(dict.fromkeys([*result.get("limitations", []), *observation["limitations"]]))
        result.update({"run_id": self.run_id, "observation_event_id": event["event_id"],
                       "synthetic": isinstance(observation.get("_example"), dict) and observation["_example"].get("synthetic") is True})
        write_json(self.path / "observations" / f"{failure_mode}.json", observation)
        write_json(self.path / "results" / f"{failure_mode}.json", result)
        self.append("oracle_result", result)
        return result

    def report(self) -> dict:
        results = [read_json(path) for path in sorted((self.path / "results").glob("F*.json"))]
        report = {"run_id": self.run_id, "generated_at": utc_now(),
                  "platform": self.manifest["config"].get("platform"), "results": results,
                  "note": "Only the tested scope is covered; no heartbeat is not proof of removal."}
        report["contains_synthetic_examples"] = any(result.get("synthetic") for result in results)
        write_json(self.path / "report.json", report)
        with (self.path / "report.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["run_id", "failure_mode", "status", "summary", "synthetic"])
            writer.writeheader()
            for result in results:
                writer.writerow({key: result.get(key, "") for key in writer.fieldnames})
        lines = [f"# ACTScope 实验报告：{self.run_id}", "", f"平台：{report['platform']}", "",
                 "此报告只反映本轮已测范围；缺少观测不表示不存在问题。", "",
                 "| 项目 | 状态 | 结论 |", "| --- | --- | --- |"]
        if report["contains_synthetic_examples"]:
            lines.insert(4, "**本报告包含合成测试数据，仅用于验证工具流程，不是任何平台的实测结果。**")
            lines.insert(5, "")
        for result in results:
            summary = str(result.get("summary", "")).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {result['failure_mode']} | {result['status']} | {summary} |")
        for result in results:
            lines.extend(["", f"## {result['failure_mode']}", "", "```json", json.dumps(result, ensure_ascii=False, indent=2), "```"])
        (self.path / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return report
