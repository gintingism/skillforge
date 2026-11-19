"""Zero-trust isolated sandbox runner for bundled agent skill scripts.

Executes Python scripts inside an ephemeral filesystem jail with network sockets,
subprocess spawning, host environment variables, and out-of-jail writes blocked.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import SkillForgeError

_SANDBOX_SITECUSTOMIZE = '''"""Injected SkillForge runtime capability jail."""
import builtins
import io
import os
import pathlib
import socket
import subprocess
import sys

_SANDBOX_ROOT = os.path.realpath(os.environ.get("SKILLFORGE_SANDBOX_ROOT", "."))
_SENSITIVE_MARKERS = (".ssh", ".aws", ".gnupg", ".env", "id_rsa", "credentials", "/etc/shadow", "/etc/passwd")

def _emit_block(category: str, detail: str) -> None:
    sys.stderr.write(f"[SANDBOX_BLOCK:{category}] {detail}\\n")
    sys.stderr.flush()

class _BlockedSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        _emit_block("NETWORK", "Socket creation denied inside SkillForge sandbox")
        raise PermissionError("[SANDBOX_BLOCK:NETWORK] Network access is disabled inside sandbox")

def _blocked_connect(*args, **kwargs):
    _emit_block("NETWORK", f"Connection attempt denied: {args[:1]}")
    raise PermissionError("[SANDBOX_BLOCK:NETWORK] Outbound connections are disabled inside sandbox")

socket.socket = _BlockedSocket  # type: ignore[misc]
socket.create_connection = _blocked_connect  # type: ignore[assignment]

def _blocked_popen(*args, **kwargs):
    _emit_block("SUBPROCESS", f"Subprocess execution denied: {args[:1]}")
    raise PermissionError("[SANDBOX_BLOCK:SUBPROCESS] Subprocess spawning is disabled inside sandbox")

def _blocked_system(cmd):
    _emit_block("SUBPROCESS", f"os.system denied: {cmd}")
    raise PermissionError("[SANDBOX_BLOCK:SUBPROCESS] Shell execution is disabled inside sandbox")

subprocess.Popen = _blocked_popen  # type: ignore[misc]
os.system = _blocked_system  # type: ignore[assignment]

_orig_open = builtins.open

def _is_within_sandbox(target_path: str) -> bool:
    try:
        real = os.path.realpath(target_path)
        return os.path.commonpath([real, _SANDBOX_ROOT]) == _SANDBOX_ROOT
    except Exception:
        return False

def _is_sensitive_path(target_path: str) -> bool:
    norm = str(target_path).replace("\\\\", "/").lower()
    return any(marker in norm for marker in _SENSITIVE_MARKERS)

def _guarded_open(file, mode="r", *args, **kwargs):
    if isinstance(file, (str, bytes, os.PathLike)):
        path_str = os.fspath(file)
        if isinstance(path_str, bytes):
            path_str = path_str.decode("utf-8", errors="replace")
        is_write = any(ch in mode for ch in ("w", "a", "x", "+"))
        if is_write and not _is_within_sandbox(path_str):
            _emit_block("FS_WRITE", f"Out-of-jail write denied: {path_str}")
            raise PermissionError(f"[SANDBOX_BLOCK:FS_WRITE] Write outside sandbox denied: {path_str}")
        if _is_sensitive_path(path_str) and not _is_within_sandbox(path_str):
            _emit_block("FS_READ", f"Sensitive host file read denied: {path_str}")
            raise PermissionError(f"[SANDBOX_BLOCK:FS_READ] Read of sensitive path denied: {path_str}")
    return _orig_open(file, mode, *args, **kwargs)

builtins.open = _guarded_open
io.open = _guarded_open
pathlib.Path.open = lambda self, mode="r", *a, **kw: _guarded_open(self, mode, *a, **kw)  # type: ignore[method-assign]

_orig_remove = os.remove
_orig_unlink = os.unlink

def _guarded_remove(path, *args, **kwargs):
    path_str = os.fspath(path)
    if isinstance(path_str, bytes):
        path_str = path_str.decode("utf-8", errors="replace")
    if not _is_within_sandbox(path_str):
        _emit_block("FS_DELETE", f"Out-of-jail delete denied: {path_str}")
        raise PermissionError(f"[SANDBOX_BLOCK:FS_DELETE] Delete outside sandbox denied: {path_str}")
    return _orig_remove(path, *args, **kwargs)

os.remove = _guarded_remove
os.unlink = _guarded_remove
'''

_BLOCK_EVENT_PATTERN = re.compile(r"\[SANDBOX_BLOCK:([A-Z_]+)\]\s*(.+)")


@dataclass
class SandboxExecutionResult:
    """Result of executing a script inside the isolated capability sandbox."""

    script_path: str
    exit_code: int
    timed_out: bool
    stdout: str
    stderr: str
    blocked_events: list[dict[str, str]] = field(default_factory=list)
    duration_ms: float = 0.0
    backend: str = "python-capability-jail"

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and len(self.blocked_events) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "script": self.script_path,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_ms": round(self.duration_ms, 2),
            "backend": self.backend,
            "blocked_events": self.blocked_events,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def _resolve_runtime_command(staged_script: Path, args: list[str]) -> tuple[list[str], str]:
    suffix = staged_script.suffix.lower()
    if suffix == ".py" or suffix == "":
        return [sys.executable, str(staged_script), *args], "python-capability-jail"
    if suffix in (".sh", ".bash"):
        bash_bin = shutil.which("bash") or "/bin/bash"
        return [bash_bin, str(staged_script), *args], "subprocess-env-jail"
    if suffix in (".js", ".mjs"):
        node_bin = shutil.which("node")
        if not node_bin:
            raise SkillForgeError("Node.js runtime ('node') not found for .js/.mjs sandbox execution.")
        return [node_bin, str(staged_script), *args], "subprocess-env-jail"
    raise SkillForgeError(f"Unsupported sandbox script extension: {suffix}")


def _wrap_with_bwrap(cmd: list[str], work_dir: Path, guard_dir: Path | None) -> list[str]:
    bwrap_cmd = [
        "bwrap",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--bind",
        str(work_dir),
        str(work_dir),
    ]
    if guard_dir is not None:
        bwrap_cmd.extend(["--ro-bind", str(guard_dir), str(guard_dir)])
    bwrap_cmd.extend(["--unshare-net", "--die-with-parent", "--chdir", str(work_dir), "--", *cmd])
    return bwrap_cmd


def run_in_sandbox(
    script_path: Path,
    script_args: list[str] | None = None,
    timeout_sec: float = 5.0,
    use_os_jail: bool = True,
) -> SandboxExecutionResult:
    """Execute a bundled script inside an ephemeral capability-jailed sandbox."""
    if not script_path.is_file():
        raise SkillForgeError(f"Script not found: {script_path}")

    args = script_args or []
    start_ns = time.perf_counter_ns()

    with tempfile.TemporaryDirectory(prefix="skillforge_jail_") as temp_dir:
        jail_root = Path(temp_dir).resolve()
        guard_dir = jail_root / "_guard"
        work_dir = jail_root / "workspace"
        guard_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)

        (guard_dir / "sitecustomize.py").write_text(_SANDBOX_SITECUSTOMIZE, encoding="utf-8")

        staged_script = work_dir / script_path.name
        shutil.copy2(script_path, staged_script)

        safe_env: dict[str, str] = {
            "PYTHONPATH": str(guard_dir),
            "SKILLFORGE_SANDBOX_ROOT": str(work_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "TEMP": str(work_dir),
            "TMP": str(work_dir),
            "HOME": str(work_dir),
            "USERPROFILE": str(work_dir),
        }
        for sys_key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATH"):
            if sys_key in os.environ:
                safe_env[sys_key] = os.environ[sys_key]

        cmd, backend = _resolve_runtime_command(staged_script, args)
        if use_os_jail and shutil.which("bwrap"):
            cmd = _wrap_with_bwrap(cmd, work_dir, guard_dir if backend == "python-capability-jail" else None)
            backend = "bwrap"

        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                cwd=work_dir,
                env=safe_env,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            exit_code = proc.returncode
            stdout = proc.stdout[:8192]
            stderr = proc.stderr[:8192]
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = 124
            stdout = (exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))[:8192]
            stderr = (exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""))[:8192]

    duration_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
    blocked_events: list[dict[str, str]] = []
    for line in stderr.splitlines():
        m = _BLOCK_EVENT_PATTERN.search(line)
        if m:
            blocked_events.append({"category": m.group(1), "detail": m.group(2).strip()})

    return SandboxExecutionResult(
        script_path=str(script_path),
        exit_code=exit_code,
        timed_out=timed_out,
        stdout=stdout,
        stderr=stderr,
        blocked_events=blocked_events,
        duration_ms=duration_ms,
        backend=backend,
    )
