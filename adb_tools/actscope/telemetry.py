"""Authenticated, append-only telemetry collector for the F5/F7 test application.

This is a research collector, not a production hosting service. Bind to loopback
by default; use HTTPS (directly or behind a TLS reverse proxy) for cloud devices.
No request executes a device command. All persistent output stays in this project.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "runs" / "collector"
MAX_BODY = 65536
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
FIELDS = {
    "run_id", "instance_id", "sequence", "sampled_at_device", "build_id",
    "a11y_component", "a11y_enabled", "a11y_sampled_at",
    "device_admin_enabled", "notification_listener_enabled",
    "service_last_heartbeat", "boot_id", "elapsed_realtime_ms",
    "clock_offset_ms", "clock_uncertainty_ms", "clock_sync_age_ms",
}


class CollectorError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def inside_project(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    resolved = path.resolve()
    if resolved != ROOT and ROOT not in resolved.parents:
        raise CollectorError("Output path must be inside the adb_tools workspace")
    return resolved


def identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise CollectorError(f"Invalid {name}: use 1–96 ASCII letters/digits/._-")
    return value


def integer(value: Any, name: str, minimum: int = 0, nullable: bool = False) -> Any:
    if value is None and nullable:
        return None
    if type(value) is not int or not minimum <= value <= 2**53 - 1:
        raise CollectorError(f"Invalid {name}: expected integer >= {minimum}")
    return value


def number(value: Any, name: str, nonnegative: bool = False) -> Any:
    if value is None:
        return None
    if type(value) not in (int, float) or not math.isfinite(value):
        raise CollectorError(f"Invalid {name}: expected finite number or null")
    if abs(value) > 2**53 - 1 or (nonnegative and value < 0):
        raise CollectorError(f"Invalid {name}: outside allowed range")
    return value


def validate_event(data: Any) -> dict:
    if not isinstance(data, dict):
        raise CollectorError("Expected a JSON object")
    extra = set(data) - FIELDS
    if extra:
        raise CollectorError("Unexpected telemetry fields: " + ", ".join(sorted(extra)))
    event = dict(data)
    for name in ("run_id", "instance_id"):
        identifier(event.get(name), name)
    integer(event.get("sequence"), "sequence", 1)
    integer(event.get("sampled_at_device"), "sampled_at_device", 1)
    for name in ("build_id", "a11y_component"):
        value = event.get(name)
        if not isinstance(value, str) or not value or len(value) > 512:
            raise CollectorError(f"Missing or invalid {name}")
    boot = event.get("boot_id")
    if boot is not None and (not isinstance(boot, str) or not boot or len(boot) > 512):
        raise CollectorError("Invalid boot_id")
    enabled = event.get("a11y_enabled")
    if enabled is not None and type(enabled) is not bool:
        raise CollectorError("a11y_enabled must be true, false or null")
    event["a11y_enabled"] = enabled
    for name in ("device_admin_enabled", "notification_listener_enabled"):
        state = event.get(name)
        if state is not None and type(state) is not bool:
            raise CollectorError(f"{name} must be true, false or null")
        event[name] = state
    for name in ("a11y_sampled_at", "service_last_heartbeat", "elapsed_realtime_ms"):
        integer(event.get(name), name, nullable=True)
    if enabled is not None and event.get("a11y_sampled_at") is None:
        raise CollectorError("Known permission state requires a11y_sampled_at")
    number(event.get("clock_offset_ms"), "clock_offset_ms")
    for name in ("clock_uncertainty_ms", "clock_sync_age_ms"):
        number(event.get(name), name, nonnegative=True)
    # Canonicalize omitted optional values so retry comparison is deterministic.
    for name in FIELDS:
        event.setdefault(name, None)
    return event


class CollectorStore:
    def __init__(self, data_dir: str | Path = DEFAULT_DATA):
        self.data_dir = inside_project(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = inside_project(self.data_dir / "telemetry.sqlite3")
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL, instance_id TEXT,
                    session_end_server_ms INTEGER, ready_server_ms INTEGER,
                    next_session_server_ms INTEGER
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    instance_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                    received_at_server INTEGER NOT NULL, payload TEXT NOT NULL,
                    UNIQUE(run_id, instance_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL, recorded_at_ms INTEGER NOT NULL,
                    kind TEXT NOT NULL, detail TEXT NOT NULL
                );
            """)
        self.db_path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.db_path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def initialize(self, run_id: str, instance_id: str | None = None) -> dict:
        identifier(run_id, "run_id")
        if instance_id:
            identifier(instance_id, "instance_id")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        try:
            with self.connect() as db:
                db.execute("INSERT INTO runs(run_id,token_hash,created_at_ms,instance_id) "
                           "VALUES(?,?,?,?)", (run_id, digest, now_ms(), instance_id))
        except sqlite3.IntegrityError as exc:
            raise CollectorError("Run already exists; do not rotate its token mid-experiment", 409) from exc
        return {"run_id": run_id, "token": token, "instance_id": instance_id}

    def ingest(self, token: str, payload: Any, received_at: int | None = None) -> dict:
        event = validate_event(payload)
        if not isinstance(token, str) or not token or len(token) > 256:
            raise CollectorError("Unauthorized", 401)
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
        received = now_ms() if received_at is None else integer(received_at, "received_at", 1)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT * FROM runs WHERE run_id=?", (event["run_id"],)).fetchone()
            digest = hashlib.sha256(token.encode()).hexdigest()
            if run is None or not hmac.compare_digest(run["token_hash"], digest):
                raise CollectorError("Unauthorized", 401)
            if run["instance_id"] and run["instance_id"] != event["instance_id"]:
                raise CollectorError("This run is bound to another installation instance", 409)
            previous = db.execute(
                "SELECT * FROM events WHERE run_id=? AND instance_id=? AND sequence=?",
                (event["run_id"], event["instance_id"], event["sequence"]),
            ).fetchone()
            if previous:
                if previous["payload"] != canonical:
                    raise CollectorError("Conflicting payload for an existing sequence", 409)
                return {"accepted": True, "duplicate": True,
                        "received_at_server": previous["received_at_server"]}
            db.execute("UPDATE runs SET instance_id=? WHERE run_id=?",
                       (event["instance_id"], event["run_id"]))
            db.execute("INSERT INTO events(run_id,instance_id,sequence,received_at_server,payload) "
                       "VALUES(?,?,?,?,?)", (event["run_id"], event["instance_id"],
                                             event["sequence"], received, canonical))
        return {"accepted": True, "duplicate": False, "received_at_server": received}

    def mark(self, run_id: str, phase: str, at_ms: int, note: str = "") -> dict:
        identifier(run_id, "run_id")
        integer(at_ms, "at_ms", 1)
        fields = {"end": "session_end_server_ms", "ready": "ready_server_ms",
                  "next": "next_session_server_ms"}
        if phase not in fields:
            raise CollectorError("Unknown lifecycle phase")
        field = fields[phase]
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None:
                raise CollectorError("Unknown run", 404)
            if run[field] is not None and run[field] != at_ms:
                raise CollectorError("Lifecycle timestamp already recorded; preserve original evidence", 409)
            proposed = dict(run)
            proposed[field] = at_ms
            values = [proposed[x] for x in fields.values() if proposed[x] is not None]
            if values != sorted(values):
                raise CollectorError("Expected end <= ready <= next timestamps")
            # field is selected only from the fixed mapping above.
            db.execute(f"UPDATE runs SET {field}=? WHERE run_id=?", (at_ms, run_id))
            db.execute("INSERT INTO audit(run_id,recorded_at_ms,kind,detail) VALUES(?,?,?,?)",
                       (run_id, now_ms(), phase, json.dumps({"at_ms": at_ms, "note": note})))
        return {"run_id": run_id, field: at_ms, "source": "operator_lifecycle_confirmation"}

    def export(self, run_id: str, no_reauthorization: bool = False) -> dict:
        identifier(run_id, "run_id")
        with self.connect() as db:
            run = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None:
                raise CollectorError("Unknown run", 404)
            rows = db.execute("SELECT * FROM events WHERE run_id=? ORDER BY event_id", (run_id,)).fetchall()
            audit = [dict(r) for r in db.execute("SELECT * FROM audit WHERE run_id=? ORDER BY audit_id", (run_id,))]
        events = []
        for row in rows:
            event = json.loads(row["payload"])
            event["received_at_server"] = row["received_at_server"]
            event["collector_event_id"] = row["event_id"]
            events.append(event)
        end = run["session_end_server_ms"]
        baseline = []
        if end is not None:
            for event in events:
                offset, uncertainty = event["clock_offset_ms"], event["clock_uncertainty_ms"]
                age = event["clock_sync_age_ms"]
                if (offset is None or uncertainty is None or age is None
                        or event["elapsed_realtime_ms"] is None or event["boot_id"] is None):
                    continue
                if uncertainty > 2000 or age > 300000:
                    continue
                upper = event["sampled_at_device"] + offset + uncertainty
                lower = event["sampled_at_device"] + offset - uncertainty
                if lower <= event["received_at_server"] <= end and upper < end:
                    baseline.append(event)
        # Validate the same wall-clock/monotonic relationship used by the oracle.
        # Arrival order can differ from sampling order when a queue retries.
        valid_baseline = []
        previous_by_boot = {}
        for event in sorted(baseline, key=lambda e: e["sequence"]):
            previous = previous_by_boot.get(event["boot_id"])
            if previous is not None:
                elapsed_delta = event["elapsed_realtime_ms"] - previous["elapsed_realtime_ms"]
                wall_delta = (event["sampled_at_device"] + event["clock_offset_ms"]
                              - previous["sampled_at_device"] - previous["clock_offset_ms"])
                tolerance = event["clock_uncertainty_ms"] + previous["clock_uncertainty_ms"] + 2000
                if elapsed_delta <= 0 or abs(wall_delta - elapsed_delta) > tolerance:
                    continue
            previous_by_boot[event["boot_id"]] = event
            valid_baseline.append(event)
        baseline = valid_baseline
        components = {event["a11y_component"] for event in baseline}
        builds = {event["build_id"] for event in baseline}
        initial = any(
            e["a11y_enabled"] is True and e["a11y_sampled_at"] is not None
            and abs(e["a11y_sampled_at"] - e["sampled_at_device"]) <= 5000
            and e["a11y_sampled_at"] + e["clock_offset_ms"] + e["clock_uncertainty_ms"] < end
            and e["a11y_sampled_at"] + e["clock_offset_ms"] - e["clock_uncertainty_ms"] <= e["received_at_server"]
            for e in baseline
        )
        return {
            "schema_version": 1, "source": "authenticated_collector",
            "expected_run_id": run_id, "expected_instance_id": run["instance_id"],
            "expected_build_id": next(iter(builds)) if len(builds) == 1 else None,
            "session_end_server_ms": end,
            "cleanup_ready_server_ms": run["ready_server_ms"],
            "next_session_server_ms": run["next_session_server_ms"],
            "baseline_telemetry_verified": len(baseline) >= 2 and len(components) == 1 and len(builds) == 1,
            "initial_a11y_enabled": initial,
            "a11y_component": next(iter(components)) if len(components) == 1 else None,
            "reauthorized": False if no_reauthorization else None,
            "min_fresh_events": 2, "clock_max_uncertainty_ms": 2000,
            "events": events, "lifecycle_audit": audit,
        }


def handler_for(store: CollectorStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ACTScopeCollector/1"

        def reply(self, status: int, payload: dict):
            body = json.dumps(payload, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/v1/time":
                self.reply(200, {"server_time_ms": now_ms()})
            elif self.path == "/healthz":
                self.reply(200, {"status": "ok"})
            else:
                self.reply(404, {"error": "Not found"})

        def do_POST(self):
            if self.path != "/v1/telemetry":
                self.reply(404, {"error": "Not found"})
                return
            try:
                if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                    raise CollectorError("Content-Type must be application/json", 415)
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    raise CollectorError("Unauthorized", 401)
                raw_length = self.headers.get("Content-Length")
                if raw_length is None:
                    raise CollectorError("Content-Length required", 411)
                try:
                    length = int(raw_length)
                except ValueError as exc:
                    raise CollectorError("Invalid Content-Length") from exc
                if not 0 < length <= MAX_BODY:
                    raise CollectorError("Request body too large or empty", 413)
                self.connection.settimeout(10)
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise CollectorError("Incomplete request body")
                def invalid_constant(value):
                    raise ValueError("Non-finite JSON value: " + value)
                data = json.loads(raw.decode("utf-8"), parse_constant=invalid_constant)
                self.reply(200, store.ingest(auth[7:], data))
            except CollectorError as exc:
                self.reply(exc.status, {"error": str(exc)})
            except (ValueError, UnicodeError):
                self.reply(400, {"error": "Invalid JSON"})
            except TimeoutError:
                self.reply(408, {"error": "Request timed out"})
            except sqlite3.Error:
                self.reply(503, {"error": "Storage temporarily unavailable"})

        def log_message(self, format: str, *args: Any):
            # Avoid logging credentials, request bodies, or attacker-chosen paths.
            pass

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8765, data_dir: str | Path = DEFAULT_DATA,
          certfile: str | None = None, keyfile: str | None = None):
    if bool(certfile) != bool(keyfile):
        raise CollectorError("Supply both --certfile and --keyfile")
    server = ThreadingHTTPServer((host, port), handler_for(CollectorStore(data_dir)))
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Collector listening on {'https' if certfile else 'http'}://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def write_json(path: Path, data: dict, exclusive: bool = False):
    path = inside_project(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x" if exclusive else "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    path.chmod(0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA))
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Register a run and save its secret provisioning file")
    init.add_argument("--run-id", required=True)
    init.add_argument("--instance-id")
    init.add_argument("--endpoint", default="https://YOUR-COLLECTOR")
    server = sub.add_parser("serve", help="Run collector; no device commands are executed")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    server.add_argument("--certfile")
    server.add_argument("--keyfile")
    for phase in ("end", "ready", "next"):
        mark = sub.add_parser(phase, help="Record operator-confirmed lifecycle milestone")
        mark.add_argument("--run-id", required=True)
        mark.add_argument("--at-ms", type=int)
        mark.add_argument("--note", default="")
    export = sub.add_parser("export", help="Export observation for F5/F7 oracle")
    export.add_argument("--run-id", required=True)
    export.add_argument("--output", required=True)
    export.add_argument("--no-reauthorization", action="store_true",
                        help="Record that the original service was not reauthorized after return")
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            serve(args.host, args.port, args.data_dir, args.certfile, args.keyfile)
            return 0
        store = CollectorStore(args.data_dir)
        if args.command == "init":
            identifier(args.run_id, "run_id")
            output = inside_project(store.data_dir / "provisioning" / f"{args.run_id}.json")
            if output.exists():
                raise CollectorError("Provisioning file exists; use a new run_id", 409)
            provisioning = store.initialize(args.run_id, args.instance_id)
            provisioning["endpoint"] = args.endpoint
            write_json(output, provisioning, exclusive=True)
            print(f"Provisioning saved (contains secret token): {output}")
        elif args.command == "export":
            output = inside_project(args.output)
            write_json(output, store.export(args.run_id, args.no_reauthorization))
            print(f"Observation saved: {output}")
        else:
            print(json.dumps(store.mark(args.run_id, args.command,
                                        args.at_ms if args.at_ms is not None else now_ms(), args.note)))
        return 0
    except (CollectorError, OSError) as exc:
        print(f"Collector error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
