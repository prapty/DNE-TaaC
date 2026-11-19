# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

import unittest
from unittest.mock import AsyncMock, Mock, patch

from taac.constants import TestCaseFailure
from taac.tasks.rbb_srv6_mysid_adjacency_task import (
    RbbSrv6MySidAdjacencyTask,
    _mysid_is_resolved,
)

_SID = "fdad:ffff:27d6::"
_RESOLVED = f"""MySid: {_SID}/48  Type: ADJACENCY_MICRO_SID
\tResolved via:
\t\tfe80::2012:1 via Port-Channel162, fboss2012
MySid: fdad:ffff:7fff::/48  Type: DECAPSULATE_AND_LOOKUP
"""
_UNRESOLVED = f"""MySid: {_SID}/48  Type: ADJACENCY_MICRO_SID
MySid: fdad:ffff:7fff::/48  Type: DECAPSULATE_AND_LOOKUP
"""


class MySidStateParserTest(unittest.TestCase):
    def test_distinguishes_resolved_and_unresolved_entries(self) -> None:
        import ipaddress

        sid = ipaddress.IPv6Address(_SID)
        self.assertTrue(_mysid_is_resolved(_RESOLVED, sid))
        self.assertFalse(_mysid_is_resolved(_UNRESOLVED, sid))

    def test_missing_entry_fails(self) -> None:
        import ipaddress

        with self.assertRaisesRegex(TestCaseFailure, "is absent"):
            _mysid_is_resolved("", ipaddress.IPv6Address(_SID))


class MySidAdjacencyTaskTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.driver = Mock()
        self.driver.async_run_cmd_on_shell = AsyncMock()
        self.driver.async_enable_ports_via_ssh = AsyncMock()
        self.shared_data = {}
        self.params = {
            "hostname": "r2.example",
            "interface": "eth1/6/5",
            "sid": _SID,
            "timeout_sec": 1,
        }

    def task(self) -> RbbSrv6MySidAdjacencyTask:
        return RbbSrv6MySidAdjacencyTask(shared_data=self.shared_data)

    async def test_unresolve_then_restore_is_owned_and_verified(self) -> None:
        self.driver.async_run_cmd_on_shell.side_effect = [_RESOLVED, _UNRESOLVED]
        with patch(
            "taac.tasks.rbb_srv6_mysid_adjacency_task.async_get_device_driver",
            AsyncMock(return_value=self.driver),
        ):
            await self.task().run({**self.params, "action": "unresolve"})
        self.driver.async_enable_ports_via_ssh.assert_awaited_once_with(
            ["eth1/6/5"], False
        )

        self.driver.async_run_cmd_on_shell.reset_mock()
        self.driver.async_run_cmd_on_shell.side_effect = None
        self.driver.async_run_cmd_on_shell.return_value = _RESOLVED
        self.driver.async_enable_ports_via_ssh.reset_mock()
        with patch(
            "taac.tasks.rbb_srv6_mysid_adjacency_task.async_get_device_driver",
            AsyncMock(return_value=self.driver),
        ):
            await self.task().run({**self.params, "action": "restore"})
        self.driver.async_enable_ports_via_ssh.assert_awaited_once_with(
            ["eth1/6/5"], True
        )

    async def test_refuses_to_take_ownership_when_already_unresolved(self) -> None:
        self.driver.async_run_cmd_on_shell.return_value = _UNRESOLVED
        with patch(
            "taac.tasks.rbb_srv6_mysid_adjacency_task.async_get_device_driver",
            AsyncMock(return_value=self.driver),
        ):
            with self.assertRaisesRegex(TestCaseFailure, "already unresolved"):
                await self.task().run({**self.params, "action": "unresolve"})
        self.driver.async_enable_ports_via_ssh.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
