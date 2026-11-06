# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""RBB SRv6-path counter-delta task (gate S25).

Asserts a real counter INCREASE across the traffic window, rather than merely
checking that a counter exists. The portable defaults measure the selected
core-egress and tail-edge path. Platforms with per-SRv6-object counters should
provide those through the documented command/regex overrides for strict
encapsulation/decapsulation evidence.

Two-phase, keyed by ``hostname:direction`` in the task's shared-data namespace
so a snapshot taken before traffic and an assert taken after traffic compare the
same counter on the same box:

* ``action="snapshot"`` — read the counter, store the baseline value.
* ``action="assert"``   — read the counter again, compute ``now - baseline`` and
  raise ``TestCaseFailure`` (a FAIL verdict) when the delta is below
  ``min_delta`` (default 1), i.e. no traffic crossed the selected measured
  path. With platform-specific SRv6-object overrides, the same result is strict
  encap/decap evidence.

The exact counter CLI + the integer-extraction regex are scenario-supplied
(``counter_cmd`` / ``counter_regex``; see ``bgp_rbb_scenario_profiles``) so the
device syntax lives with the scenario (§5.4) and the task stays generic. This is
a registered Task (not a new ``CheckName``) for the same schema-stability reason
as ``rbb_srv6_verify`` — no Thrift edit, no ``all_health_checks`` change.
"""

import math
import re
import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_SNAPSHOT = "snapshot"
_ASSERT = "assert"


class RbbSrv6CounterDeltaTask(BaseTask):
    """Snapshot/assert a selected path or SRv6-object counter on one DUT."""

    # pyre-ignore[15]
    NAME: str = "rbb_srv6_counter_delta"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    def _extract(self, output: str, regex: str) -> int | None:
        """Sum every captured integer, or return ``None`` when none matched."""
        total = 0
        found = False
        for m in re.finditer(regex, output):
            try:
                total += int(m.group(1).replace(",", ""))
                found = True
            except (IndexError, ValueError):
                continue
        return total if found else None

    async def run(self, params: dict[str, t.Any]) -> None:
        """Snapshot or assert an SRv6 counter delta.

        params:
            hostname: DUT to query (required).
            action: "snapshot" or "assert" (required).
            counter_cmd: shell command whose stdout carries the counter (required).
            counter_regex: regex with one integer capture group (required).
            direction: "encap" / "decap" label for the shared-data key + logs.
            min_delta: minimum required increase for "assert" (default 1).
            reference_hostname/reference_direction: optional previously asserted
                counter delta to compare against.
            min_reference_ratio: require this counter delta to be at least this
                fraction of the referenced delta.
            gate: human-readable gate label (optional).
        """
        hostname = params.get("hostname") or self.hostname
        if not hostname:
            raise ValueError("rbb_srv6_counter_delta requires 'hostname'")
        action = params.get("action")
        if action not in (_SNAPSHOT, _ASSERT):
            raise ValueError(
                f"rbb_srv6_counter_delta 'action' must be {_SNAPSHOT!r} or "
                f"{_ASSERT!r}, got {action!r}"
            )
        counter_cmd = params.get("counter_cmd")
        if not counter_cmd:
            raise ValueError("rbb_srv6_counter_delta requires 'counter_cmd'")
        counter_regex = params.get("counter_regex")
        if not counter_regex:
            raise ValueError("rbb_srv6_counter_delta requires 'counter_regex'")
        direction = params.get("direction", "srv6")
        gate = params.get("gate", "rbb_srv6_counter_delta")
        key = f"{hostname}:{direction}"
        min_delta = int(params.get("min_delta", 1))
        if action == _ASSERT and min_delta < 1:
            raise ValueError(
                "rbb_srv6_counter_delta 'min_delta' must be at least 1 for "
                f"an assert action, got {min_delta}"
            )
        reference_hostname = params.get("reference_hostname")
        reference_direction = params.get("reference_direction")
        min_reference_ratio = float(params.get("min_reference_ratio", 0.0))
        if not math.isfinite(min_reference_ratio) or min_reference_ratio < 0:
            raise ValueError(
                "rbb_srv6_counter_delta 'min_reference_ratio' must be a "
                "finite non-negative number"
            )
        if min_reference_ratio and not (
            reference_hostname and reference_direction
        ):
            raise ValueError(
                "reference_hostname and reference_direction are required when "
                "min_reference_ratio is set"
            )

        driver = await async_get_device_driver(hostname)
        output = await driver.async_run_cmd_on_shell(counter_cmd) or ""
        value = self._extract(output, counter_regex)
        if value is None:
            raise TestCaseFailure(
                f"[{gate}] counter regex did not match output on {hostname}: "
                f"{counter_regex!r}"
            )

        if action == _SNAPSHOT:
            self._data[key] = value
            self.logger.info(
                f"{hostname} -- [{gate}] {direction} counter baseline={value}"
            )
            return

        if key in self._data:
            baseline = self._data[key]
        else:
            baseline = None
        if baseline is None:
            raise TestCaseFailure(
                f"[{gate}] no {direction} baseline recorded on {hostname} "
                f"(snapshot step must run before assert)"
            )
        delta = value - baseline
        self.logger.info(
            f"{hostname} -- [{gate}] {direction} counter now={value} "
            f"baseline={baseline} delta={delta} (min={min_delta})"
        )
        if delta < min_delta:
            raise TestCaseFailure(
                f"[{gate}] selected {direction}-path counter delta on {hostname} was "
                f"{delta} (< required {min_delta}); expected traffic to "
                f"{direction} across the core"
            )
        self._data[f"{key}:delta"] = delta

        if min_reference_ratio:
            reference_key = f"{reference_hostname}:{reference_direction}:delta"
            # _data can be BaseTask's prefixed shared-data view.  That view
            # implements membership and indexed lookup, while dict.get()
            # would read the wrapper's empty local dict instead of the shared
            # backing store.
            reference_delta = (
                self._data[reference_key]
                if reference_key in self._data
                else None
            )
            if reference_delta is None:
                raise TestCaseFailure(
                    f"[{gate}] no asserted reference delta recorded for "
                    f"{reference_hostname}:{reference_direction}"
                )
            required_delta = math.ceil(reference_delta * min_reference_ratio)
            ratio = delta / reference_delta
            self.logger.info(
                f"{hostname} -- [{gate}] {direction} delta={delta}; "
                f"reference={reference_delta} ratio={ratio:.6f} "
                f"(min_ratio={min_reference_ratio})"
            )
            if delta < required_delta:
                raise TestCaseFailure(
                    f"[{gate}] selected {direction}-path counter delta on "
                    f"{hostname} was {delta}, only {ratio:.6f} of the reference "
                    f"delta {reference_delta}; required at least "
                    f"{min_reference_ratio:.6f} ({required_delta})"
                )
