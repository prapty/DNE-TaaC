# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Fail-closed checks for IXIA capabilities required by RBB scenarios."""

from __future__ import annotations

import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask


class RbbIxiaCapabilityTask(BaseTask):
    """Verify backend behavior before a resilience disruption begins."""

    NAME: str = "rbb_ixia_capability"

    async def run(self, params: dict[str, t.Any]) -> None:
        allowed = {"gate", "require_controller_traffic_stats_reset"}
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(f"rbb_ixia_capability unsupported fields: {unknown}")
        gate = str(params.get("gate") or self.NAME)
        require_reset = params.get("require_controller_traffic_stats_reset", False)
        if not isinstance(require_reset, bool):
            raise TypeError("require_controller_traffic_stats_reset must be boolean")
        if not require_reset:
            raise ValueError("rbb_ixia_capability requires at least one capability")

        supports_reset = getattr(
            self.ixia, "supports_controller_traffic_stats_reset", None
        )
        if not callable(supports_reset) or not supports_reset():
            raise TestCaseFailure(
                f"[{gate}] IXIA backend {type(self.ixia).__name__} cannot reset "
                "controller traffic counters; isolated resilience loss windows "
                "require the RESTPy/TaacIxia backend"
            )


__all__ = ["RbbIxiaCapabilityTask"]
