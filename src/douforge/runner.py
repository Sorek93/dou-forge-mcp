"""OpenSSH execution with bounded capture and explicit timeout semantics."""
from __future__ import annotations

import asyncio
import os
import signal
import time
from collections.abc import Sequence

from .config import Config, ForgeError


def ssh_argv(config: Config, alias: str, command: str) -> list[str]:
    # alias is taken ONLY from administrator-validated configuration, not tool input.
    argv = ["ssh"]
    if config.ssh_config:
        argv += ["-F", config.ssh_config]
    argv += ["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
             "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
             "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ControlPath=none",
             "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=5",
             "-o", "ServerAliveCountMax=2", "--", alias, command]
    return argv


async def run_process(argv: Sequence[str], *, timeout_s: float, output_bytes: int,
                      hard_output_bytes: int) -> dict:
    if os.name != "posix":
        raise ForgeError("Controller currently requires Linux or macOS")
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
    buckets = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}
    captured = 0
    limited = asyncio.Event()
    timed_out = False

    async def read(stream, name):
        nonlocal captured
        while chunk := await stream.read(8192):
            totals[name] += len(chunk)
            remaining = max(0, output_bytes - captured)
            buckets[name].extend(chunk[:remaining])
            captured += min(len(chunk), remaining)
            if sum(totals.values()) > hard_output_bytes:
                limited.set()

    async def stop():
        # This terminates the local SSH group. Remote descendant termination is NOT guaranteed.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), 0.5)
        except asyncio.TimeoutError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()

    readers = [asyncio.create_task(read(proc.stdout, "stdout")),
               asyncio.create_task(read(proc.stderr, "stderr"))]
    async def completed():
        await proc.wait()
        await asyncio.gather(*readers)
    done_task = asyncio.create_task(completed())
    limit_task = asyncio.create_task(limited.wait())
    try:
        finished, _ = await asyncio.wait({done_task, limit_task}, timeout=timeout_s,
                                        return_when=asyncio.FIRST_COMPLETED)
        timed_out = not finished
        if timed_out or limited.is_set():
            await stop()
        try:
            await asyncio.wait_for(asyncio.shield(done_task), 1)
        except asyncio.TimeoutError:
            done_task.cancel()
    except BaseException:
        await stop()
        raise
    finally:
        for task in [done_task, limit_task, *readers]:
            if not task.done():
                task.cancel()
        await asyncio.gather(done_task, limit_task, *readers, return_exceptions=True)
    result = {"exit_code": proc.returncode, "stdout": bytes(buckets["stdout"]).decode("utf-8", "replace"),
              "stderr": bytes(buckets["stderr"]).decode("utf-8", "replace"),
              "bytes_out": totals["stdout"], "bytes_err": totals["stderr"],
              "captured_bytes": captured, "truncated": sum(totals.values()) > captured,
              "output_limited": limited.is_set(), "timed_out": timed_out,
              "duration_ms": round((time.monotonic() - started) * 1000),
              "remote_termination_verified": False}
    result["ok"] = proc.returncode == 0 and not timed_out and not limited.is_set()
    return result


async def run_ssh(config: Config, alias: str, command: str) -> dict:
    return await run_process(ssh_argv(config, alias, command), timeout_s=config.timeout_s,
                             output_bytes=config.output_bytes, hard_output_bytes=config.hard_output_bytes)
