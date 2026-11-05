# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Self-cleaning Phase-2 TC-01 recursive iBGP route playbook."""

from __future__ import annotations

import re

from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import create_run_task_step
from taac.test_as_a_config.types import Playbook, Step
from taac.testconfigs.routing.util.bgp_rbb_recursive_route_profiles import (
    RbbRecursiveRouteProfile,
)

_TASK_NAME = "rbb_recursive_route"


def _step(
    profile: RbbRecursiveRouteProfile,
    head_hostname: str,
    tail_hostname: str,
    action: str,
) -> Step:
    return create_run_task_step(
        task_name=_TASK_NAME,
        params_dict={
            "action": action,
            "head_hostname": head_hostname,
            "tail_hostname": tail_hostname,
            "route_prefix": profile.route_prefix,
            "recursive_next_hop": profile.recursive_next_hop,
        },
        description=f"[{profile.testplan_id}] {action} recursive iBGP route",
        start_traffic=False,
    )


def create_rbb_recursive_route_playbook(
    profile: RbbRecursiveRouteProfile,
    *,
    r1_hostname: str,
    r2_hostname: str,
) -> Playbook:
    if not r1_hostname.strip() or not r2_hostname.strip() or r1_hostname == r2_hostname:
        raise ValueError("TC-01 requires distinct R1 and R2 hostnames")
    stages = [
        create_steps_stage(
            steps=[_step(profile, r1_hostname, r2_hostname, "precheck")],
            description=f"{profile.testplan_id}: prove test resources are pristine",
        ),
        create_steps_stage(
            steps=[_step(profile, r1_hostname, r2_hostname, "install")],
            description=(
                f"{profile.testplan_id}: originate service prefix with remote "
                "loopback next hop"
            ),
        ),
        create_steps_stage(
            steps=[_step(profile, r1_hostname, r2_hostname, "verify")],
            description=(
                f"{profile.testplan_id}: verify BGPD-to-OPENR recursive resolution"
            ),
        ),
        create_steps_stage(
            steps=[_step(profile, r1_hostname, r2_hostname, "cleanup")],
            description=f"{profile.testplan_id}: restore BGP baseline and withdrawal",
        ),
    ]
    return Playbook(
        name=profile.playbook_name,
        description=f"{profile.testplan_id} [FULL]: {profile.title}",
        prechecks=[],
        postchecks=[],
        stages=stages,
        cleanup_steps=[_step(profile, r1_hostname, r2_hostname, "cleanup")],
        traffic_items_to_start=None,
        device_regexes=[f"^{re.escape(r1_hostname)}$"],
    )


__all__ = ["create_rbb_recursive_route_playbook"]
