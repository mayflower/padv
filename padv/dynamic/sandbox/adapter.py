from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass

from padv.config.schema import SandboxConfig


@dataclass(slots=True)
class SandboxResult:
    ok: bool
    action: str
    output: str


def _run_cmd(action: str, cmd: str, timeout: int | None = None) -> SandboxResult:
    if not cmd.strip():
        return SandboxResult(ok=True, action=action, output="skipped:no_command_configured")

    try:
        proc = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return SandboxResult(
            ok=False,
            action=action,
            output=f"command timed out ({timeout}s): {cmd}",
        )
    output = (proc.stdout or "") + (proc.stderr or "")
    return SandboxResult(ok=proc.returncode == 0, action=action, output=output.strip())


def deploy(config: SandboxConfig) -> SandboxResult:
    return _run_cmd("deploy", config.deploy_cmd)


def reset(config: SandboxConfig) -> SandboxResult:
    return _run_cmd("reset", config.reset_cmd)


def status(config: SandboxConfig) -> SandboxResult:
    return _run_cmd("status", config.status_cmd)


def logs(config: SandboxConfig) -> SandboxResult:
    return _run_cmd("logs", config.logs_cmd)
