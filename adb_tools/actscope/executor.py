"""ADB transport with explicit serial, timeouts and complete command evidence."""
from __future__ import annotations
import hashlib
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from .store import RunStore, utc_now


@dataclass
class CommandResult:
    argv: list[str]
    started_at: str
    duration_s: float
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class AdbExecutor:
    def __init__(self, serial: str, store: RunStore, binary: str = "adb", timeout_s: float = 15):
        if not serial or serial.startswith("REPLACE_"):
            raise ValueError("Configure an explicit platform ADB serial before executing")
        self.serial, self.store, self.binary = serial, store, binary
        self.timeout_s = min(max(float(timeout_s), 0.1), 300.0)

    def run(self, args: list[str], *, timeout_s: float | None = None) -> CommandResult:
        argv = [self.binary, "-s", self.serial, *args]
        started, monotonic = utc_now(), time.monotonic()
        timeout = self.timeout_s if timeout_s is None else min(max(timeout_s, 0.1), 300.0)
        try:
            proc = subprocess.run(argv, shell=False, capture_output=True, text=True, errors="replace", timeout=timeout)
            result = CommandResult(argv, started, time.monotonic() - monotonic, proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as error:
            decode = lambda x: x.decode(errors="replace") if isinstance(x, bytes) else x or ""
            result = CommandResult(argv, started, time.monotonic() - monotonic, None, decode(error.stdout), decode(error.stderr), True)
        except OSError as error:
            result = CommandResult(argv, started, time.monotonic() - monotonic, None, "", str(error))
        self.store.append("command", asdict(result))
        return result

    def shell(self, command: str, *, timeout_s: float | None = None) -> CommandResult:
        # adb shell passes a single remote command; no host shell is used.
        return self.run(["shell", command], timeout_s=timeout_s)

    def shell_args(self, args: list[str], **kwargs) -> CommandResult:
        return self.shell(shlex.join(args), **kwargs)
