# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Shared TestConfig for full Phase-2 TC-16/17/18/32/106 validation."""

from __future__ import annotations

import ipaddress
import os
import re

from ixia.ixia import types as ixia_types
from taac.constants import DEFAULT_SRC_MAC_ADDRESS
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import BasicTrafficItemConfig, TrafficEndpoint

from taac.playbooks.routing.factories.qual_rbb.rbb_srv6_mysid_playbook import (
    create_rbb_srv6_tc16_playbook,
    create_rbb_srv6_tc17_playbook,
    create_rbb_srv6_tc18_playbook,
    create_rbb_srv6_tc32_playbook,
    create_rbb_srv6_tc106_playbook,
)
from taac.task_definitions import create_ixia_sync_raw_source_macs_task
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _build_rbb_test_config,
    _resolve_topology,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import build_rbb_inventories
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology
from taac.utils.packet_header_utils import create_field, create_packet_header


def _raw_ipv6_headers(destination: str) -> list[taac_types.PacketHeader]:
    return [
        create_packet_header(
            stack_regex="^ethernet$",
            fields=[
                create_field(
                    field_regex="Destination MAC Address",
                    field_attrs={
                        "ValueType": "increment",
                        "StepValue": "00:00:00:00:00:00",
                        "CountValue": 1,
                    },
                    references={
                        "StartValue": taac_types.Reference(
                            type=taac_types.ReferenceType.DST_MAC_ADDRESS
                        )
                    },
                ),
                create_field(
                    field_regex="Source MAC Address",
                    field_attrs={
                        "ValueType": "increment",
                        "StartValue": DEFAULT_SRC_MAC_ADDRESS,
                        "StepValue": "00:00:00:00:00:00",
                        "CountValue": 1,
                    },
                ),
            ],
        ),
        create_packet_header(
            stack_regex="^ipv6$",
            append_to_stack_regex="^ethernet$",
            fields=[
                create_field(
                    field_regex="Source Address",
                    field_attrs={
                        "ValueType": "increment",
                        "StepValue": "::1",
                        "CountValue": 1,
                    },
                    references={
                        "StartValue": taac_types.Reference(
                            type=taac_types.ReferenceType.SRC_IPV6_ADDRESS
                        )
                    },
                ),
                create_field(
                    field_regex="Destination Address",
                    field_attrs={"SingleValue": destination},
                ),
                create_field(field_regex="Hop Limit", field_attrs={"SingleValue": 64}),
            ],
        ),
    ]


def _negative_traffic_item(
    topology: RbbTopology, *, name: str, destination: str
) -> BasicTrafficItemConfig:
    interface = topology.r2.primary_ixia_interface
    if not interface:
        raise ValueError(f"{name} requires the R2 IXIA edge")
    endpoint = TrafficEndpoint(name=f"{topology.r2.hostname}:{interface}")
    return BasicTrafficItemConfig(
        name=name,
        src_endpoints=[endpoint],
        dest_endpoints=[endpoint],
        traffic_type=ixia_types.TrafficType.RAW,
        line_rate=1000,
        line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
        frame_size_settings=ixia_types.FrameSize(
            type=ixia_types.FrameSizeType.FIXED, fixed_size=128
        ),
        bidirectional=False,
        allow_self_destined=True,
        merge_destinations=True,
        src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
        packet_headers=_raw_ipv6_headers(destination),
        skip_default_l4_protocol=True,
    )


def _unknown_usid() -> str:
    sid = os.environ.get("TAAC_RBB_UNKNOWN_USID") or C.default_usid(
        SRV6_3_USIDS_PROFILE.locator, 0x7FFE
    )
    address = ipaddress.ip_address(sid)
    known = {
        ipaddress.ip_address(value.split("/", 1)[0])
        for value in (
            SRV6_3_USIDS_PROFILE.usid_head,
            SRV6_3_USIDS_PROFILE.usid_mid,
            SRV6_3_USIDS_PROFILE.decap_sid,
        )
    }
    locator = ipaddress.ip_network(SRV6_3_USIDS_PROFILE.locator, strict=False)
    if address not in locator or address in known:
        raise ValueError(
            "TAAC_RBB_UNKNOWN_USID must be inside the locator and distinct "
            "from every configured RBB MySID"
        )
    return str(address)


def create_rbb_srv6_mysid_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_P2_MYSID_FULL_VALIDATION",
    r2_mac: str | None = None,
) -> taac_types.TestConfig:
    topology = _resolve_topology(topology, include_traffic=True)
    r1, r2 = build_rbb_inventories(topology)
    r2_mac = r2_mac or os.environ.get("TAAC_RBB_R2_MAC")
    if not r2_mac or not re.fullmatch(
        r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", r2_mac
    ):
        raise ValueError(
            "mysid-validation RAW traffic requires TAAC_RBB_R2_MAC as a "
            "six-octet colon-delimited DUT MAC"
        )
    unknown_usid = _unknown_usid()
    raw_items = [
        _negative_traffic_item(
            topology,
            name=C.TRAFFIC_ITEM_TC32_MYSID_DROP,
            # A configured uA with no next micro-segment is selected, then
            # rejected by the SRv6 local-SID action.
            destination=SRV6_3_USIDS_PROFILE.usid_mid,
        ),
        _negative_traffic_item(
            topology,
            name=C.TRAFFIC_ITEM_TC106_UNKNOWN_USID,
            destination=unknown_usid,
        ),
    ]
    raw_regex = (
        f"^(?:{C.TRAFFIC_ITEM_TC32_MYSID_DROP}|"
        f"{C.TRAFFIC_ITEM_TC106_UNKNOWN_USID})$"
    )
    return _build_rbb_test_config(
        name=name,
        profile=SRV6_3_USIDS_PROFILE,
        playbooks=[
            create_rbb_srv6_tc16_playbook(topology=topology),
            create_rbb_srv6_tc17_playbook(topology=topology),
            create_rbb_srv6_tc18_playbook(topology=topology),
            create_rbb_srv6_tc32_playbook(topology=topology),
            create_rbb_srv6_tc106_playbook(
                topology=topology, unknown_usid=unknown_usid
            ),
        ],
        r1=r1,
        r2=r2,
        topology=topology,
        include_traffic=True,
        extra_traffic_items=raw_items,
        extra_setup_tasks=[
            create_ixia_sync_raw_source_macs_task(traffic_item_regex=raw_regex)
        ],
        endpoint_macs={r2.device_name: r2_mac.lower()},
    )


__all__ = ["create_rbb_srv6_mysid_test_config"]
