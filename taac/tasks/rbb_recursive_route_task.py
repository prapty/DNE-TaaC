# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Reversible Phase-2 TC-01 recursive iBGP route lifecycle.

The task originates one test-owned IPv6 service prefix on R2 with R2's
loopback as its explicit iBGP next hop.  On R1 it proves that the service
prefix is BGPD-owned, that the loopback is OPENR-owned, and that both FIB
entries resolve to the same non-empty underlay next-hop set.  Cleanup restores
the exact pre-run bgp.json and verifies that the service route is withdrawn.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import time
import typing as t

from taac.constants import TestCaseFailure
from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.tasks.base_task import BaseTask
from taac.tasks.rbb_edge_config_utils import (
    async_apply_backup_metadata,
    async_backup_before_overwrite,
    async_read_file_or_none,
    async_restore_backup,
    async_write_json_file,
)
from taac.tasks.rbb_state_audit_task import (
    _client_id,
    _preferred_fib_client_ids,
    _resolved_next_hops,
    _route_prefix,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_PRECHECK = "precheck"
_INSTALL = "install"
_VERIFY = "verify"
_CLEANUP = "cleanup"
_ACTIONS = frozenset((_PRECHECK, _INSTALL, _VERIFY, _CLEANUP))
_BACKUP_SUFFIX = ".taac-rbb-recursive-orig"


def _network(value: t.Any) -> ipaddress.IPv6Network:
    try:
        network = ipaddress.ip_network(str(value), strict=True)
    except ValueError as exc:
        raise ValueError("route_prefix must be a canonical IPv6 prefix") from exc
    if network.version != 6:
        raise ValueError("route_prefix must be IPv6")
    return t.cast(ipaddress.IPv6Network, network)


def _address(value: t.Any) -> ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise ValueError("recursive_next_hop must be an IPv6 address") from exc
    if address.version != 6:
        raise ValueError("recursive_next_hop must be IPv6")
    return t.cast(ipaddress.IPv6Address, address)


def _route_matches(routes: t.Iterable[t.Any], prefix: str) -> list[t.Any]:
    return [route for route in routes if _route_prefix(route) == prefix]


def _fib_detail(
    details: t.Iterable[t.Any], prefix: str, client_id: int
) -> t.Any | None:
    matching = [detail for detail in details if _route_prefix(detail) == prefix]
    preferred = [
        detail
        for detail in matching
        if client_id in _preferred_fib_client_ids(detail)
    ]
    if len(preferred) != 1:
        owners = sorted(
            {
                owner
                for detail in matching
                for owner in _preferred_fib_client_ids(detail)
            }
        )
        raise TestCaseFailure(
            f"route {prefix} has {len(preferred)} preferred FIB entries for "
            f"client {client_id}; observed_client_ids={owners}"
        )
    return preferred[0]


class RbbRecursiveRouteTask(BaseTask):
    """Install, verify, and remove the TC-01 test-owned BGP route."""

    # pyrefly: ignore [bad-override-mutable-attribute]
    NAME: str = "rbb_recursive_route"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    async def run(self, params: dict[str, t.Any]) -> None:
        allowed = {
            "action",
            "head_hostname",
            "tail_hostname",
            "route_prefix",
            "recursive_next_hop",
            "timeout_seconds",
            "poll_interval_seconds",
        }
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(
                f"rbb_recursive_route contains unsupported fields: {unknown}"
            )
        action = str(params.get("action", ""))
        if action not in _ACTIONS:
            raise ValueError(
                f"rbb_recursive_route action must be one of {sorted(_ACTIONS)}"
            )
        head = str(params.get("head_hostname") or "").strip()
        tail = str(params.get("tail_hostname") or "").strip()
        if not head or not tail or head == tail:
            raise ValueError("distinct head_hostname and tail_hostname are required")
        prefix = _network(params.get("route_prefix")).with_prefixlen
        next_hop = str(_address(params.get("recursive_next_hop")))
        timeout = self._finite_number(params.get("timeout_seconds", 60), "timeout")
        interval = self._finite_number(
            params.get("poll_interval_seconds", 2), "poll interval"
        )
        if timeout < 0 or interval <= 0:
            raise ValueError("timeout must be non-negative and poll interval positive")

        if action == _PRECHECK:
            await self._precheck(head, tail, prefix, next_hop)
        elif action == _INSTALL:
            await self._install(tail, prefix, next_hop)
        elif action == _VERIFY:
            await self._poll(
                lambda: self._verify(head, prefix, next_hop), timeout, interval
            )
        else:
            await self._cleanup(head, tail, prefix, timeout, interval)

    @staticmethod
    def _finite_number(value: t.Any, label: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{label} must be a finite number")
        result = float(value)
        if not math.isfinite(result):
            raise ValueError(f"{label} must be a finite number")
        return result

    async def _poll(
        self,
        operation: t.Callable[[], t.Awaitable[None]],
        timeout: float,
        interval: float,
    ) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                await operation()
                return
            except TestCaseFailure:
                if time.monotonic() >= deadline:
                    raise
                await asyncio.sleep(
                    min(interval, max(0.0, deadline - time.monotonic()))
                )

    async def _precheck(
        self, head: str, tail: str, prefix: str, next_hop: str
    ) -> None:
        tail_driver = await async_get_device_driver(tail)
        raw = await async_read_file_or_none(tail_driver, C.BGP_CONFIG_PATH)
        if not raw:
            raise TestCaseFailure(f"{tail}: missing {C.BGP_CONFIG_PATH}")
        try:
            config = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TestCaseFailure(f"{tail}: invalid bgp.json: {exc}") from exc
        networks = config.get("networks6")
        if not isinstance(networks, list) or any(
            not isinstance(item, dict) for item in networks
        ):
            raise TestCaseFailure(f"{tail}: bgp.json networks6 must be a list")
        configured = {str(item.get("prefix")) for item in networks}
        if prefix in configured:
            raise TestCaseFailure(
                f"{tail}: test prefix {prefix} already exists in bgp.json"
            )
        if f"{next_hop}/128" not in configured:
            raise TestCaseFailure(
                f"{tail}: recursive loopback {next_hop}/128 is not originated"
            )
        await self._assert_absent(head, prefix)

    async def _install(self, tail: str, prefix: str, next_hop: str) -> None:
        driver = await async_get_device_driver(tail)
        uid = str(await driver.async_run_cmd_on_shell("id -u") or "").strip()
        if uid != "0":
            raise TestCaseFailure(f"{tail}: TC-01 install requires root SSH")
        raw = await async_read_file_or_none(driver, C.BGP_CONFIG_PATH)
        if not raw:
            raise TestCaseFailure(f"{tail}: missing {C.BGP_CONFIG_PATH}")
        try:
            config = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TestCaseFailure(f"{tail}: invalid bgp.json: {exc}") from exc
        networks = config.get("networks6")
        if not isinstance(networks, list) or any(
            not isinstance(item, dict) for item in networks
        ):
            raise TestCaseFailure(f"{tail}: bgp.json networks6 must be a list")
        if any(str(item.get("prefix")) == prefix for item in networks):
            raise TestCaseFailure(f"{tail}: refusing to overwrite existing {prefix}")
        if not any(
            str(item.get("prefix")) == f"{next_hop}/128" for item in networks
        ):
            raise TestCaseFailure(
                f"{tail}: recursive loopback {next_hop}/128 is not originated"
            )

        await async_backup_before_overwrite(
            driver,
            C.BGP_CONFIG_PATH,
            self.logger,
            tail,
            backup_suffix=_BACKUP_SUFFIX,
        )
        config["networks6"] = [
            *networks,
            {"prefix": prefix, "nexthop": next_hop, "install_to_fib": False},
        ]
        try:
            await async_write_json_file(
                driver, C.BGP_CONFIG_PATH, config, hostname=tail
            )
            await async_apply_backup_metadata(
                driver,
                C.BGP_CONFIG_PATH,
                tail,
                backup_suffix=_BACKUP_SUFFIX,
            )
            await driver.async_restart_service(FbossSystemctlServiceName.BGP)
            self._data[f"{tail}:{prefix}"] = True
        except Exception as exc:
            try:
                await async_restore_backup(
                    driver,
                    C.BGP_CONFIG_PATH,
                    self.logger,
                    tail,
                    backup_suffix=_BACKUP_SUFFIX,
                )
                await driver.async_restart_service(FbossSystemctlServiceName.BGP)
            except Exception as rollback_exc:  # noqa: BLE001
                raise TestCaseFailure(
                    f"{tail}: TC-01 install failed ({exc}); rollback also failed "
                    f"({rollback_exc})"
                ) from exc
            raise TestCaseFailure(
                f"{tail}: TC-01 install failed and was rolled back: {exc}"
            ) from exc

    async def _verify(self, head: str, prefix: str, next_hop: str) -> None:
        driver = await async_get_device_driver(head)
        bgpd_id = _client_id("BGPD")
        openr_id = _client_id("OPENR")
        loopback_prefix = f"{next_hop}/128"
        bgpd_routes = list(await driver.async_get_route_table_by_client(bgpd_id))
        openr_routes = list(await driver.async_get_route_table_by_client(openr_id))
        service = _route_matches(bgpd_routes, prefix)
        loopback = _route_matches(openr_routes, loopback_prefix)
        if len(service) != 1 or len(loopback) != 1:
            raise TestCaseFailure(
                f"{head}: expected one BGPD {prefix} and one OPENR "
                f"{loopback_prefix}; observed {len(service)} and {len(loopback)}"
            )
        _, rib_hops, _ = _resolved_next_hops(service[0])
        if rib_hops != {next_hop}:
            raise TestCaseFailure(
                f"{head}: BGPD {prefix} next hop expected {next_hop}, "
                f"observed={sorted(rib_hops)}"
            )

        details = list(await driver.async_get_route_table_details())
        service_fib = _fib_detail(details, prefix, bgpd_id)
        loopback_fib = _fib_detail(details, loopback_prefix, openr_id)
        service_entries, _, _ = _resolved_next_hops(service_fib)
        loopback_entries, _, _ = _resolved_next_hops(loopback_fib)
        service_set = set(service_entries)
        loopback_set = set(loopback_entries)
        if not service_set or service_set != loopback_set:
            raise TestCaseFailure(
                f"{head}: {prefix} did not recursively resolve through "
                f"{loopback_prefix}; service={sorted(service_set)} "
                f"loopback={sorted(loopback_set)}"
            )
        self.logger.info(
            f"{head} -- [phase2:TC-01] recursive BGPD/OpenR resolution passed"
        )

    async def _assert_absent(self, head: str, prefix: str) -> None:
        driver = await async_get_device_driver(head)
        bgpd_id = _client_id("BGPD")
        routes = list(await driver.async_get_route_table_by_client(bgpd_id))
        if _route_matches(routes, prefix):
            raise TestCaseFailure(f"{head}: BGPD route {prefix} is still present")
        if any(
            _route_prefix(detail) == prefix
            for detail in await driver.async_get_route_table_details()
        ):
            raise TestCaseFailure(f"{head}: FIB route {prefix} is still present")

    async def _cleanup(
        self, head: str, tail: str, prefix: str, timeout: float, interval: float
    ) -> None:
        driver = await async_get_device_driver(tail)
        ownership_key = f"{tail}:{prefix}"
        owned = (
            ownership_key in self._data and self._data[ownership_key] is True
        )
        restored = await async_restore_backup(
            driver,
            C.BGP_CONFIG_PATH,
            self.logger,
            tail,
            backup_suffix=_BACKUP_SUFFIX,
        )
        if restored:
            await driver.async_restart_service(FbossSystemctlServiceName.BGP)
        if restored or owned:
            await self._poll(
                lambda: self._assert_absent(head, prefix), timeout, interval
            )
            self._data[ownership_key] = False
        else:
            self.logger.info(
                f"{tail} -- TC-01 cleanup found no task-owned BGP snapshot"
            )


__all__ = ["RbbRecursiveRouteTask"]
