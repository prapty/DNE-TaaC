# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Integration tests for the named SRv6 NHG TestConfig."""

import ipaddress
import json
import runpy
import unittest
from pathlib import Path
from unittest import mock

from taac.testconfigs.routing.factories.qual_rbb.rbb_named_nhg_test_config import (
    create_rbb_named_nhg_test_config,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology() -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="nhg-r1.example",
            core_pcs=(CorePortChannel("port-channel1", ("eth1/1",)),),
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="nhg-r2.example",
            core_pcs=(CorePortChannel("port-channel1", ("eth1/1",)),),
            ixia_edges=(IxiaEdge("eth1/5", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbNamedNhgTestConfigTest(unittest.TestCase):
    def test_default_config_exposes_six_independent_playbooks(self) -> None:
        config = create_rbb_named_nhg_test_config(_topology())

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p2_tc01_recursive_route",
                "rbb_p2_tc02_program_named_srv6_nhg",
                "rbb_p2_tc03_loopback_admin_distance",
                "rbb_p2_tc04_service_prefix_srv6_nhg",
                "rbb_p2_tc06_named_nhg_forward_reference",
                "rbb_p2_tc07_resolve_named_nhg_forward_reference",
            ],
        )

    def test_default_config_reserves_and_configures_ixia(self) -> None:
        config = create_rbb_named_nhg_test_config(_topology())

        self.assertFalse(config.skip_ixia_protocol_verification)
        self.assertEqual(len(config.basic_port_configs or []), 2)
        self.assertEqual(
            [item.name for item in config.basic_traffic_item_configs or []],
            ["RBB_R1_TO_R2_NAMED_NHG"],
        )
        tail_port = (config.basic_port_configs or [])[1]
        advertised = (
            tail_port.device_group_configs[0]
            .v6_bgp_config.route_scales[0]
            .v6_route_scale
        )
        tail_prefix = ipaddress.ip_network(C.TAIL_DEST_PREFIX)
        self.assertEqual(advertised.starting_prefixes, str(tail_prefix.network_address))
        self.assertEqual(advertised.prefix_length, tail_prefix.prefixlen)
        self.assertEqual(advertised.prefix_count, 1)
        self.assertEqual(len(config.endpoints), 2)
        for endpoint in config.endpoints:
            self.assertTrue(endpoint.ixia_needed)
            self.assertTrue(endpoint.ixia_ports)
            self.assertTrue(endpoint.direct_ixia_connections)

        tc01_params = [
            json.loads(json.loads(step.input_json)["task"]["params"]["json_params"])
            for stage in config.playbooks[0].stages
            for step in stage.steps
        ]
        self.assertTrue(
            all(not params["baseline_route_expected"] for params in tc01_params)
        )

    def test_edge_overlay_advertises_tail_prefix_via_r2_loopback(self) -> None:
        with mock.patch.object(C, "EDGE_EBGP_ENABLED", True):
            config = create_rbb_named_nhg_test_config(_topology())

        edge_params = [
            json.loads(task.params.json_params)
            for task in config.setup_tasks or []
            if task.task_name == "rbb_edge_ebgp"
        ]
        self.assertEqual(len(edge_params), 2)
        self.assertEqual(edge_params[1]["ibgp_srv6_nexthop"], C.R2_LOOPBACK_V6)
        self.assertEqual(
            edge_params[1]["withdraw_network6_prefix"], C.TAIL_DEST_PREFIX
        )

    def test_explicit_selection_keeps_catalog_order(self) -> None:
        config = create_rbb_named_nhg_test_config(
            _topology(), testplan_ids=["phase2:TC-07", "phase2:TC-02"]
        )

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p2_tc02_program_named_srv6_nhg",
                "rbb_p2_tc07_resolve_named_nhg_forward_reference",
            ],
        )

    def test_tc01_can_be_selected_independently(self) -> None:
        config = create_rbb_named_nhg_test_config(
            _topology(), testplan_ids=["phase2:TC-01"]
        )

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            ["rbb_p2_tc01_recursive_route"],
        )
        self.assertTrue(config.skip_ixia_protocol_verification)
        self.assertIsNone(config.basic_traffic_item_configs)

    def test_tc03_tc04_selection_reuses_infrastructure(self) -> None:
        config = create_rbb_named_nhg_test_config(
            _topology(), testplan_ids=["phase2:TC-04", "phase2:TC-03"]
        )

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p2_tc03_loopback_admin_distance",
                "rbb_p2_tc04_service_prefix_srv6_nhg",
            ],
        )
        self.assertFalse(config.skip_ixia_protocol_verification)
        self.assertEqual(
            [item.name for item in config.basic_traffic_item_configs or []],
            ["RBB_R1_TO_R2_NAMED_NHG"],
        )

    def test_empty_selection_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "selection is empty"):
            create_rbb_named_nhg_test_config(_topology(), testplan_ids=[])

    def test_example_wrapper_exports_factory_result(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[4] / "examples" / "rbb_named_nhg_config.py"
        )
        sentinel = object()
        target = (
            "taac.testconfigs.routing.factories.qual_rbb."
            "rbb_named_nhg_test_config.create_rbb_named_nhg_test_config"
        )
        with mock.patch(target, return_value=sentinel):
            result = runpy.run_path(str(wrapper))
        self.assertIs(result["test_config"], sentinel)


if __name__ == "__main__":
    unittest.main()
