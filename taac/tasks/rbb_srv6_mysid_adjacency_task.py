# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Temporarily unresolve and restore an RBB adjacency MySID."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask
from taac.utils.driver_factory import async_get_device_driver

_UNRESOLVE = "unresolve"
_RESTORE = "restore"
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _mysid_is_resolved(output: str, sid: ipaddress.IPv6Address) -> bool:
    """Return the selected entry's state from ``fboss2 show mysid``."""
    selected: list[str] | None = None
    for line in output.splitlines():
        match = re.match(r"^MySid:\s+(\S+)/(\d+)\s+", line)
        if match:
            try:
                address = ipaddress.IPv6Address(match.group(1))
            except ipaddress.AddressValueError:
                selected = None
                continue
            if address == sid:
                selected = [line]
            elif selected is not None:
                break
        elif selected is not None:
            selected.append(line)
    if selected is None:
        raise TestCaseFailure(f"MySID {sid} is absent from 'fboss2 show mysid'")
    return any("Resolved via:" in line for line in selected)


class RbbSrv6MySidAdjacencyTask(BaseTask):
    """Drive the adjacency MySID into the SAI local-SID-drop state safely."""

    NAME = "rbb_srv6_mysid_adjacency"

    async def _wait_for_state(
        self,
        driver: t.Any,
        sid: ipaddress.IPv6Address,
        *,
        resolved: bool,
        timeout_sec: float,
    ) -> None:
        deadline = time.monotonic() + timeout_sec
        while True:
            output = await driver.async_run_cmd_on_shell("fboss2 show mysid")
            if _mysid_is_resolved(output, sid) is resolved:
                return
            if time.monotonic() >= deadline:
                state = "resolved" if resolved else "unresolved"
                raise TestCaseFailure(
                    f"MySID {sid} did not become {state} within {timeout_sec:g}s"
                )
            await asyncio.sleep(1)

    async def run(self, params: dict[str, t.Any]) -> None:
        hostname = params.get("hostname") or self.hostname
        if not isinstance(hostname, str) or not hostname:
            raise ValueError("rbb_srv6_mysid_adjacency requires 'hostname'")
        action = params.get("action")
        if action not in {_UNRESOLVE, _RESTORE}:
            raise ValueError(
                "rbb_srv6_mysid_adjacency action must be 'unresolve' or 'restore'"
            )
        interface = params.get("interface")
        if not isinstance(interface, str) or not _INTERFACE_RE.fullmatch(interface):
            raise ValueError(
                "rbb_srv6_mysid_adjacency requires a valid 'interface'"
            )
        try:
            sid = ipaddress.IPv6Address(params.get("sid"))
            timeout_sec = float(params.get("timeout_sec", 30))
        except (ipaddress.AddressValueError, TypeError, ValueError) as exc:
            raise ValueError("invalid MySID or timeout") from exc
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")

        key = f"{hostname}:{interface}:{sid}"
        best_effort = bool(params.get("best_effort", False))
        try:
            driver = await async_get_device_driver(hostname)
            if action == _UNRESOLVE:
                output = await driver.async_run_cmd_on_shell("fboss2 show mysid")
                if not _mysid_is_resolved(output, sid):
                    raise TestCaseFailure(
                        f"refusing to mutate {hostname}:{interface}: MySID {sid} "
                        "was already unresolved"
                    )
                # Set ownership before the mutation so cleanup recovers a port
                # even if the remote command succeeds but its SSH reply is lost.
                self._data[key] = True
                await driver.async_enable_ports_via_ssh([interface], False)
                await self._wait_for_state(
                    driver, sid, resolved=False, timeout_sec=timeout_sec
                )
                return

            if key not in self._data or not self._data[key]:
                return
            await driver.async_enable_ports_via_ssh([interface], True)
            await self._wait_for_state(
                driver, sid, resolved=True, timeout_sec=timeout_sec
            )
            self._data[key] = False
        except Exception as exc:
            if not best_effort:
                raise
            self.logger.error(
                f"[rbb_srv6_mysid_adjacency] best-effort {action} failed for "
                f"{hostname}:{interface}: {type(exc).__name__}: {exc}"
            )


__all__ = ["RbbSrv6MySidAdjacencyTask"]
