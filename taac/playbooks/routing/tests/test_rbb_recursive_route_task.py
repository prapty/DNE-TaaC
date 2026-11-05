# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for the Phase-2 TC-01 recursive-route registered task."""

import ipaddress
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestCaseFailure
from taac.tasks.rbb_recursive_route_task import RbbRecursiveRouteTask
from taac.tasks.registry import TASK_NAME_TO_CLASS

_MODULE = "taac.tasks.rbb_recursive_route_task"


def _binary(address: str, if_name: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(addr=ipaddress.ip_address(address).packed, ifName=if_name)


def _route(prefix: str, next_hops=()) -> SimpleNamespace:
    network = ipaddress.ip_network(prefix, strict=True)
    return SimpleNamespace(
        dest=SimpleNamespace(
            ip=SimpleNamespace(addr=network.network_address.packed),
            prefixLength=network.prefixlen,
        ),
        nextHopAddrs=list(next_hops),
    )


def _detail(prefix: str, client_id: int, next_hops) -> SimpleNamespace:
    route = _route(prefix)
    return SimpleNamespace(
        dest=route.dest,
        nextHopMulti=[SimpleNamespace(clientId=client_id, isPreferred=True)],
        nextHops=[SimpleNamespace(address=value) for value in next_hops],
        adminDistance=None,
    )


class RbbRecursiveRouteTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_task_is_registered(self) -> None:
        self.assertIs(TASK_NAME_TO_CLASS["rbb_recursive_route"], RbbRecursiveRouteTask)

    async def test_verify_proves_rib_next_hop_and_equal_resolved_fib(self) -> None:
        driver = MagicMock()
        service = _route("2001:db8:ff01::/64", (_binary("2001:db8:0:2::1"),))
        loopback = _route("2001:db8:0:2::1/128")
        driver.async_get_route_table_by_client = AsyncMock(
            side_effect=lambda client: [service] if client == 0 else [loopback]
        )
        resolved = (_binary("fe80::2", "fboss2001"),)
        driver.async_get_route_table_details = AsyncMock(
            return_value=[
                _detail("2001:db8:ff01::/64", 0, resolved),
                _detail("2001:db8:0:2::1/128", 786, resolved),
            ]
        )
        task = RbbRecursiveRouteTask(logger=MagicMock())

        with (
            patch(f"{_MODULE}.async_get_device_driver", AsyncMock(return_value=driver)),
            patch(f"{_MODULE}._client_id", side_effect={"BGPD": 0, "OPENR": 786}.get),
        ):
            await task._verify(
                "r1.example", "2001:db8:ff01::/64", "2001:db8:0:2::1"
            )

    async def test_verify_rejects_nonrecursive_fib(self) -> None:
        driver = MagicMock()
        service = _route("2001:db8:ff01::/64", (_binary("2001:db8:0:2::1"),))
        loopback = _route("2001:db8:0:2::1/128")
        driver.async_get_route_table_by_client = AsyncMock(
            side_effect=lambda client: [service] if client == 0 else [loopback]
        )
        driver.async_get_route_table_details = AsyncMock(
            return_value=[
                _detail(
                    "2001:db8:ff01::/64",
                    0,
                    (_binary("fe80::99", "fboss2099"),),
                ),
                _detail(
                    "2001:db8:0:2::1/128",
                    786,
                    (_binary("fe80::2", "fboss2001"),),
                ),
            ]
        )
        task = RbbRecursiveRouteTask(logger=MagicMock())

        with (
            patch(f"{_MODULE}.async_get_device_driver", AsyncMock(return_value=driver)),
            patch(f"{_MODULE}._client_id", side_effect={"BGPD": 0, "OPENR": 786}.get),
            self.assertRaisesRegex(TestCaseFailure, "did not recursively resolve"),
        ):
            await task._verify(
                "r1.example", "2001:db8:ff01::/64", "2001:db8:0:2::1"
            )

    async def test_install_writes_only_test_owned_network_and_restarts_bgp(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(return_value="0")
        driver.async_restart_service = AsyncMock()
        task = RbbRecursiveRouteTask(logger=MagicMock())
        base = '{"networks6": [{"prefix": "2001:db8:0:2::1/128"}]}'

        with (
            patch(f"{_MODULE}.async_get_device_driver", AsyncMock(return_value=driver)),
            patch(f"{_MODULE}.async_read_file_or_none", AsyncMock(return_value=base)),
            patch(f"{_MODULE}.async_backup_before_overwrite", AsyncMock()),
            patch(f"{_MODULE}.async_apply_backup_metadata", AsyncMock()),
            patch(f"{_MODULE}.async_write_json_file", AsyncMock()) as write,
        ):
            await task._install(
                "r2.example", "2001:db8:ff01::/64", "2001:db8:0:2::1"
            )

        document = write.await_args.args[2]
        self.assertEqual(
            document["networks6"][-1],
            {
                "prefix": "2001:db8:ff01::/64",
                "nexthop": "2001:db8:0:2::1",
                "install_to_fib": False,
            },
        )
        driver.async_restart_service.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
