"""Configuration adapters for semi-automatic platform lifecycle operations.

Xiaomi/Alltesting presets do not claim verified web automation. The operator uses
platform UI and imports its receipt, time and identity as an auditable event.
"""
from __future__ import annotations
from datetime import datetime
from .executor import AdbExecutor, sha256_file
from .store import RunStore, project_path, utc_now

EVENT_TYPES = {"session_started", "session_ended", "cleanup_ready", "session_reacquired", "debug_prepared", "probe_prepared", "installation_submitted", "installation_finished", "recovery_attempt", "note"}


class PlatformAdapter:
    def __init__(self, store: RunStore):
        self.store = store
        self.config = store.manifest["config"]

    def capabilities(self) -> dict:
        configured = self.config.get("capabilities", {})
        return {"platform": self.config.get("platform", "manual"),
                "adapter": self.config.get("adapter", "manual"),
                "verification": "configuration_only_until_runtime_observed",
                "remote_adb": configured.get("remote_adb"),
                "wireless_debugging": configured.get("wireless_debugging"),
                "shizuku": configured.get("shizuku"),
                "a11y": configured.get("a11y"),
                "reacquire_device": configured.get("reacquire_device"),
                "install_routes": configured.get("install_routes", ["platform_ui"]),
                "manual_steps": self.config.get("manual_steps", {})}

    def connect_debug(self) -> AdbExecutor:
        if self.config.get("capabilities", {}).get("remote_adb") is not True:
            raise ValueError("remote_adb must be verified/configured true; this adapter never provisions credentials")
        adb = self.config.get("adb", {})
        return AdbExecutor(adb.get("serial", ""), self.store, adb.get("binary", "adb"), adb.get("timeout_s", 15))

    def record_event(self, kind: str, *, time: str | None = None, note: str = "", evidence: str = "", device_id: str = "") -> dict:
        if kind not in EVENT_TYPES:
            raise ValueError(f"Event must be one of {sorted(EVENT_TYPES)}")
        event_time = time or utc_now()
        parsed = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Event time must include timezone")
        if kind != "note" and not note.strip():
            raise ValueError("Lifecycle events require a note describing observed platform evidence")
        if evidence:
            project_path(evidence, must_exist=True)
        return self.store.append(kind, {"time": event_time, "note": note, "evidence": evidence,
                                       "device_id": device_id, "source": "operator_observation"})

    def deploy_app(self, apk: str, route: str, *, active: bool = False) -> dict:
        path = project_path(apk, must_exist=True)
        artifact = {"apk": str(path), "sample_sha256": sha256_file(path), "route": route}
        if route not in self.capabilities()["install_routes"]:
            raise ValueError("Route is not configured")
        if route == "adb":
            if not active:
                return {**artifact, "executed": False, "instruction": "Pass --active to submit this APK via ADB"}
            result = self.connect_debug().run(["install", "-r", str(path)], timeout_s=180)
            artifact.update({"executed": True, "transport_success": result.ok, "stdout": result.stdout, "stderr": result.stderr,
                             "final_state": "unknown", "note": "Install output alone does not establish completed platform security scanning"})
        else:
            artifact.update({"executed": False, "instruction": self.config.get("manual_steps", {}).get("deploy_app", "Submit in platform UI, then import final installation observation")})
        self.store.append("deploy_app", artifact)
        return artifact
