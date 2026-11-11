# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Full Phase-2 TC-16/17/18/32/106 MySID validation."""

from __future__ import annotations

import ipaddress
import re

from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config.types import Playbook, Step

from taac.health_checks.healthcheck_definitions import (
    create_ixia_packet_loss_check,
)
from taac.playbooks.routing.factories.qual_rbb.rbb_srv6_tail_decap_playbook import (
    _best_effort_cleanup_step,
    _counter_step_no_implicit_start,
    _direct_route_step_no_implicit_start,
    _verify_step_no_implicit_start,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_clear_traffic_stats_step,
    create_ixia_api_step,
    create_longevity_step,
    create_run_task_step,
    create_stop_traffic_step,
    create_validation_step,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
    Srv6Profile,
    srv6_decap_counter_spec,
    srv6_ingress_drop_counter_spec,
    srv6_midpoint_counter_spec,
    srv6_possible_egress_counter_spec,
    srv6_usid_shift_counter_specs,
    verify_route_owner_te_agent_spec,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    RbbTopology,
    validate_rbb_topology,
)

_WARMUP_SECONDS = 5


def _start_one(name: str) -> Step:
    return create_ixia_api_step(
        api_name="start_traffic_items",
        args_dict={"traffic_item_regex": f"^{re.escape(name)}$"},
        description=f"Start only {name}",
        start_traffic=False,
    )


def _loss(name: str, *, expected: bool, description: str) -> Step:
    thresholds = [
        hc_types.PacketLossThreshold(
            names=[name],
            metric=hc_types.PacketLossMetric.PERCENTAGE,
            str_value=C.PACKET_LOSS_THRESHOLD_PCT,
            comparison=hc_types.ComparisonType.LESS_THAN_EQUAL_TO,
            expect_packet_loss=False,
        )
    ]
    if expected:
        # expect_packet_loss is a distinct non-zero-loss guard in TAAC and
        # intentionally bypasses comparison. Keep it, then add a second strict
        # threshold that enforces complete loss numerically.
        thresholds = [
            hc_types.PacketLossThreshold(
                names=[name],
                metric=hc_types.PacketLossMetric.PERCENTAGE,
                expect_packet_loss=True,
            ),
            hc_types.PacketLossThreshold(
                names=[name],
                metric=hc_types.PacketLossMetric.PERCENTAGE,
                str_value="100",
                comparison=hc_types.ComparisonType.GREATER_THAN_EQUAL_TO,
                expect_packet_loss=False,
            ),
        ]
    return create_validation_step(
        point_in_time_checks=[
            create_ixia_packet_loss_check(
                thresholds=thresholds,
                skip_traffic_items=[
                    item
                    for item in (
                        C.TRAFFIC_ITEM_R1_TO_R2,
                        C.TRAFFIC_ITEM_TC32_MYSID_DROP,
                        C.TRAFFIC_ITEM_TC106_UNKNOWN_USID,
                    )
                    if item != name
                ],
                sleep_time=2,
            )
        ],
        description=description,
        start_traffic=False,
        fail_fast=True,
    )


def _mysid_state_step(
    hostname: str,
    profile: Srv6Profile,
    *,
    gate: str = "phase2:TC-17",
    sid: str | None = None,
    behavior: str = C.SRV6_BEHAVIOR_ADJACENCY,
    prefix_length: int | None = None,
    require_resolved: bool = True,
) -> Step:
    sid = sid or profile.usid_mid
    prefix_length = prefix_length or (
        ipaddress.ip_network(profile.locator, strict=False).prefixlen + 16
    )
    return create_run_task_step(
        task_name="rbb_state_audit",
        params_dict={
            "hostname": hostname,
            "gate": gate,
            "mysids": [
                {
                    "sid": sid,
                    "behavior": behavior,
                    "require_resolved": require_resolved,
                    "prefix_length": prefix_length,
                }
            ],
        },
        description=f"{gate} exact resolved {behavior} MySID LPM entry audit",
        start_traffic=False,
    )


def create_rbb_srv6_tc17_playbook(
    *, topology: RbbTopology, profile: Srv6Profile = SRV6_3_USIDS_PROFILE
) -> Playbook:
    """Prove the R2 MySID table is programmed and consulted by real traffic."""
    validate_rbb_topology(topology, require_ixia=True)
    r1, r2 = topology.r1.hostname, topology.r2.hostname
    midpoint = srv6_midpoint_counter_spec("r2", topology)
    stages = [
        create_steps_stage(
            steps=[
                _mysid_state_step(r2, profile),
                _verify_step_no_implicit_start(
                    r2,
                    {
                        "gate": "phase2:TC-17",
                        "show_cmd": "fboss2 show hw-object SRV6",
                        "expect_contains": [profile.usid_mid.split("/", 1)[0]],
                    },
                ),
            ],
            description="TC-17 MySID software and ASIC programming",
        ),
        create_steps_stage(
            steps=[
                _direct_route_step_no_implicit_start(r1, "install", profile),
                _verify_step_no_implicit_start(
                    r1, verify_route_owner_te_agent_spec(profile)
                ),
            ],
            description="TC-17 install exact three-uSID steering route",
        ),
        create_steps_stage(
            steps=[
                create_stop_traffic_step(),
                _counter_step_no_implicit_start(r2, "snapshot", midpoint),
                create_clear_traffic_stats_step(start_traffic=False),
                _start_one(C.TRAFFIC_ITEM_R1_TO_R2),
                create_longevity_step(
                    duration=_WARMUP_SECONDS,
                    description="TC-17 midpoint traffic window",
                    start_traffic=False,
                ),
                _loss(
                    C.TRAFFIC_ITEM_R1_TO_R2,
                    expected=False,
                    description="TC-17 traffic crosses the midpoint without loss",
                ),
                _counter_step_no_implicit_start(r2, "assert", midpoint),
                create_stop_traffic_step(),
            ],
            description="TC-17 live IXIA midpoint lookup validation",
        ),
        create_steps_stage(
            steps=[_direct_route_step_no_implicit_start(r1, "delete", profile)],
            description="TC-17 withdraw temporary steering route",
        ),
    ]
    return Playbook(
        name="rbb_p2_tc17_mysid_table",
        description="phase2:TC-17 [FULL]: MySID table programmed and consulted",
        stages=stages,
        prechecks=[],
        postchecks=[],
        cleanup_steps=[_best_effort_cleanup_step(r1, profile)],
        device_regexes=[f"^{re.escape(r1)}$"],
    )


def _with_reference(
    spec: dict[str, object], *, hostname: str, direction: str
) -> dict[str, object]:
    return {
        **spec,
        "reference_hostname": hostname,
        "reference_direction": direction,
        "min_reference_ratio": 0.8,
    }


def _uA_forwarding_playbook(
    *,
    topology: RbbTopology,
    testplan_id: str,
    profile: Srv6Profile,
) -> Playbook:
    """Build TC-16 or TC-18 over the real midpoint->head->tail zigzag."""
    if testplan_id not in ("phase2:TC-16", "phase2:TC-18"):
        raise ValueError(f"unsupported uA forwarding case {testplan_id!r}")
    validate_rbb_topology(topology, require_ixia=True)
    r1, r2 = topology.r1.hostname, topology.r2.hostname

    if testplan_id.endswith("16"):
        midpoint = {
            **srv6_midpoint_counter_spec("r2", topology),
            "gate": testplan_id,
            "direction": "tc16_midpoint_egress",
        }
        decap = {
            **srv6_decap_counter_spec("r2", topology),
            "gate": testplan_id,
            "direction": "tc16_decap_egress",
        }
        counters: list[tuple[str, dict[str, object]]] = [
            (r2, midpoint),
            (r2, decap),
        ]
        state_steps = [
            _mysid_state_step(r2, profile, gate=testplan_id),
            _verify_step_no_implicit_start(
                r2,
                {
                    "gate": testplan_id,
                    "show_cmd": "fboss2 show hw-object SRV6",
                    "expect_contains": [profile.usid_mid.split("/", 1)[0]],
                },
            ),
        ]
        name = "rbb_p2_tc16_end_ua_processing"
        title = "End.uA midpoint processing"
    else:
        counters = [
            (hostname, dict(spec))
            for hostname, spec in srv6_usid_shift_counter_specs(topology)
        ]
        state_steps = [
            _mysid_state_step(r2, profile, gate=testplan_id),
            _mysid_state_step(
                r1,
                profile,
                gate=testplan_id,
                sid=profile.usid_head,
            ),
            _verify_step_no_implicit_start(
                r2,
                {
                    "gate": testplan_id,
                    "show_cmd": "fboss2 show hw-object SRV6",
                    "expect_contains": [
                        profile.usid_mid.split("/", 1)[0],
                    ],
                },
            ),
            _verify_step_no_implicit_start(
                r1,
                {
                    "gate": testplan_id,
                    "show_cmd": "fboss2 show hw-object SRV6",
                    "expect_contains": [profile.usid_head.split("/", 1)[0]],
                },
            ),
        ]
        name = "rbb_p2_tc18_mysid_lpm_shift_forward"
        title = "MySID LPM shift-and-forward"

    reference_hostname, reference_spec = counters[0]
    reference_direction = str(reference_spec["direction"])
    assertions = [
        _counter_step_no_implicit_start(
            reference_hostname, "assert", reference_spec
        )
    ]
    assertions.extend(
        _counter_step_no_implicit_start(
            hostname,
            "assert",
            _with_reference(
                spec,
                hostname=reference_hostname,
                direction=reference_direction,
            ),
        )
        for hostname, spec in counters[1:]
    )

    return Playbook(
        name=name,
        description=f"{testplan_id} [FULL] [TWO-NODE ADAPTATION]: {title}",
        stages=[
            create_steps_stage(
                steps=state_steps,
                description=f"{testplan_id} exact software and ASIC MySID state",
            ),
            create_steps_stage(
                steps=[
                    _direct_route_step_no_implicit_start(r1, "install", profile),
                    _verify_step_no_implicit_start(
                        r1, verify_route_owner_te_agent_spec(profile)
                    ),
                ],
                description=f"{testplan_id} install exact packed uSID carrier",
            ),
            create_steps_stage(
                steps=[
                    create_stop_traffic_step(),
                    *(
                        _counter_step_no_implicit_start(hostname, "snapshot", spec)
                        for hostname, spec in counters
                    ),
                    create_clear_traffic_stats_step(start_traffic=False),
                    _start_one(C.TRAFFIC_ITEM_R1_TO_R2),
                    create_longevity_step(
                        duration=_WARMUP_SECONDS,
                        description=f"{testplan_id} uA forwarding window",
                        start_traffic=False,
                    ),
                    _loss(
                        C.TRAFFIC_ITEM_R1_TO_R2,
                        expected=False,
                        description=f"{testplan_id} uA path delivers without loss",
                    ),
                    *assertions,
                    create_stop_traffic_step(),
                ],
                description=(
                    f"{testplan_id} lossless IXIA delivery and correlated uA path"
                ),
            ),
            create_steps_stage(
                steps=[
                    _direct_route_step_no_implicit_start(r1, "delete", profile),
                ],
                description=f"{testplan_id} withdraw temporary test state",
            ),
        ],
        prechecks=[],
        postchecks=[],
        cleanup_steps=[_best_effort_cleanup_step(r1, profile)],
        device_regexes=[f"^{re.escape(r1)}$"],
    )


def create_rbb_srv6_tc16_playbook(
    *, topology: RbbTopology, profile: Srv6Profile = SRV6_3_USIDS_PROFILE
) -> Playbook:
    return _uA_forwarding_playbook(
        topology=topology, testplan_id="phase2:TC-16", profile=profile
    )


def create_rbb_srv6_tc18_playbook(
    *, topology: RbbTopology, profile: Srv6Profile = SRV6_3_USIDS_PROFILE
) -> Playbook:
    return _uA_forwarding_playbook(
        topology=topology, testplan_id="phase2:TC-18", profile=profile
    )


def _negative_playbook(
    *,
    topology: RbbTopology,
    testplan_id: str,
    traffic_item: str,
    counter: str,
    check_all_egresses: bool,
    sid: str,
) -> Playbook:
    r2 = topology.r2.hostname
    drop = srv6_ingress_drop_counter_spec("r2", counter, topology)
    egress = srv6_possible_egress_counter_spec("r2", topology)
    snapshots = [_counter_step_no_implicit_start(r2, "snapshot", drop)]
    assertions = [_counter_step_no_implicit_start(r2, "assert", drop)]
    if check_all_egresses:
        snapshots.append(_counter_step_no_implicit_start(r2, "snapshot", egress))
        assertions.append(_counter_step_no_implicit_start(r2, "assert", egress))
    return Playbook(
        name=(
            "rbb_p2_tc32_local_sid_drop"
            if testplan_id.endswith("32")
            else "rbb_p2_tc106_unknown_usid"
        ),
        description=(
            f"{testplan_id} [FULL]: "
            + (
                "SAI local-SID-drop telemetry"
                if testplan_id.endswith("32")
                else "unknown-uSID clean drop"
            )
        ),
        stages=[
            create_steps_stage(
                steps=[
                    _verify_step_no_implicit_start(
                        r2,
                        {
                            "gate": testplan_id,
                            "show_cmd": "fboss2 show mysid",
                            **(
                                {
                                    "expect_contains": [
                                        sid,
                                        C.SRV6_BEHAVIOR_ADJACENCY,
                                    ]
                                }
                                if testplan_id.endswith("32")
                                else {"expect_absent": [sid]}
                            ),
                        },
                    )
                ],
                description=(
                    f"{testplan_id} prove the injected SID's MySID membership"
                ),
            ),
            create_steps_stage(
                steps=[
                    create_stop_traffic_step(),
                    *snapshots,
                    create_clear_traffic_stats_step(start_traffic=False),
                    _start_one(traffic_item),
                    create_longevity_step(
                        duration=_WARMUP_SECONDS,
                        description=f"{testplan_id} negative traffic window",
                        start_traffic=False,
                    ),
                    _loss(
                        traffic_item,
                        expected=True,
                        description=f"{testplan_id} packets are completely dropped",
                    ),
                    *assertions,
                    create_stop_traffic_step(),
                ],
                description=f"{testplan_id} IXIA loss and exact ASIC counter evidence",
            )
        ],
        prechecks=[],
        postchecks=[],
        cleanup_steps=[create_stop_traffic_step()],
        device_regexes=[f"^{re.escape(r2)}$"],
    )


def create_rbb_srv6_tc32_playbook(*, topology: RbbTopology) -> Playbook:
    return _negative_playbook(
        topology=topology,
        testplan_id="phase2:TC-32",
        traffic_item=C.TRAFFIC_ITEM_TC32_MYSID_DROP,
        counter="mysid",
        check_all_egresses=False,
        sid=SRV6_3_USIDS_PROFILE.usid_mid,
    )


def create_rbb_srv6_tc106_playbook(
    *, topology: RbbTopology, unknown_usid: str
) -> Playbook:
    return _negative_playbook(
        topology=topology,
        testplan_id="phase2:TC-106",
        traffic_item=C.TRAFFIC_ITEM_TC106_UNKNOWN_USID,
        counter="unknown",
        check_all_egresses=True,
        sid=unknown_usid,
    )


__all__ = [
    "create_rbb_srv6_tc16_playbook",
    "create_rbb_srv6_tc17_playbook",
    "create_rbb_srv6_tc18_playbook",
    "create_rbb_srv6_tc32_playbook",
    "create_rbb_srv6_tc106_playbook",
]
