# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

import json
import unittest

from ixia.ixia import types as ixia_types
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config.types import StepName

from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_mysid_test_config import (
    create_rbb_srv6_mysid_test_config,
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
            hostname="mysid-r1.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="mysid-r2.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/6", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


def _steps(playbook):
    return [step for stage in playbook.stages or [] for step in stage.steps or []]


def _tasks(playbook):
    result = []
    for step in _steps(playbook):
        if step.name != StepName.RUN_TASK_STEP:
            continue
        task = json.loads(step.input_json)["task"]
        result.append((task["task_name"], json.loads(task["params"]["json_params"])))
    return result


class RbbSrv6MySidTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = create_rbb_srv6_mysid_test_config(
            _topology(), r2_mac="02:00:00:00:00:02"
        )

    def test_one_shared_config_contains_five_full_playbooks(self) -> None:
        self.assertEqual(
            [playbook.name for playbook in self.config.playbooks or []],
            [
                "rbb_p2_tc16_end_ua_processing",
                "rbb_p2_tc17_mysid_table",
                "rbb_p2_tc18_mysid_lpm_shift_forward",
                "rbb_p2_tc32_local_sid_drop",
                "rbb_p2_tc106_unknown_usid",
            ],
        )
        self.assertTrue(
            all(
                "[FULL]" in playbook.description
                for playbook in self.config.playbooks or []
            )
        )

    def test_raw_items_target_known_terminal_and_unknown_usids(self) -> None:
        items = self.config.basic_traffic_item_configs or []
        self.assertEqual(
            [item.name for item in items],
            [
                C.TRAFFIC_ITEM_R1_TO_R2,
                C.TRAFFIC_ITEM_TC32_MYSID_DROP,
                C.TRAFFIC_ITEM_TC106_UNKNOWN_USID,
            ],
        )
        for item in items[1:]:
            self.assertEqual(item.traffic_type, ixia_types.TrafficType.RAW)
            self.assertTrue(item.allow_self_destined)
            self.assertTrue(item.skip_default_l4_protocol)
            self.assertEqual(item.line_rate, 1000)
        destinations = []
        for item in items[1:]:
            ipv6 = (item.packet_headers or [])[1]
            field = next(
                field
                for field in ipv6.fields or []
                if field.query.regex == "Destination Address"
            )
            destinations.append(json.loads(field.attrs_json)["SingleValue"])
        self.assertEqual(destinations[0], C.SRV6_USID_MID)
        self.assertNotIn(
            destinations[1],
            {C.SRV6_USID_HEAD, C.SRV6_USID_MID, C.SRV6_DECAP_SID},
        )

    def test_tc17_requires_state_asic_and_midpoint_delta(self) -> None:
        playbook = (self.config.playbooks or [])[1]
        tasks = _tasks(playbook)
        audit = next(params for name, params in tasks if name == "rbb_state_audit")
        self.assertEqual(audit["mysids"][0]["behavior"], C.SRV6_BEHAVIOR_ADJACENCY)
        self.assertTrue(audit["mysids"][0]["require_resolved"])
        self.assertEqual(audit["mysids"][0]["prefix_length"], 64)
        verifies = [params for name, params in tasks if name == "rbb_srv6_verify"]
        self.assertTrue(
            any(
                item["show_cmd"] == "fboss2 show hw-object SRV6"
                for item in verifies
            )
        )
        counters = [
            params for name, params in tasks if name == "rbb_srv6_counter_delta"
        ]
        self.assertEqual(
            [(item["direction"], item["action"]) for item in counters],
            [("midpoint_egress", "snapshot"), ("midpoint_egress", "assert")],
        )

    def test_tc16_correlates_midpoint_and_final_delivery(self) -> None:
        playbook = (self.config.playbooks or [])[0]
        self.assertIn("phase2:TC-16 [FULL]", playbook.description)
        tasks = _tasks(playbook)
        audit = next(params for name, params in tasks if name == "rbb_state_audit")
        self.assertEqual(audit["gate"], "phase2:TC-16")
        self.assertEqual(audit["mysids"][0]["prefix_length"], 64)
        counters = [
            params for name, params in tasks if name == "rbb_srv6_counter_delta"
        ]
        self.assertEqual(
            [(item["direction"], item["action"]) for item in counters],
            [
                ("tc16_midpoint_egress", "snapshot"),
                ("tc16_decap_egress", "snapshot"),
                ("tc16_midpoint_egress", "assert"),
                ("tc16_decap_egress", "assert"),
            ],
        )
        decap_assert = counters[-1]
        self.assertEqual(decap_assert["reference_hostname"], "mysid-r2.example")
        self.assertEqual(
            decap_assert["reference_direction"], "tc16_midpoint_egress"
        )
        self.assertEqual(decap_assert["min_reference_ratio"], 0.8)

    def test_tc18_proves_every_shift_and_forward_leg(self) -> None:
        playbook = (self.config.playbooks or [])[2]
        self.assertIn("phase2:TC-18 [FULL]", playbook.description)
        tasks = _tasks(playbook)
        audits = [params for name, params in tasks if name == "rbb_state_audit"]
        self.assertEqual(
            [item["hostname"] for item in audits],
            ["mysid-r2.example", "mysid-r1.example"],
        )
        self.assertEqual(
            [item["mysids"][0]["prefix_length"] for item in audits],
            [64, 64],
        )
        binding_actions = [
            params["action"]
            for name, params in tasks
            if name == "rbb_srv6_binding_mysid"
        ]
        self.assertEqual(binding_actions, [])
        hw_checks = [
            params
            for name, params in tasks
            if name == "rbb_srv6_verify"
            and params["show_cmd"] == "fboss2 show hw-object SRV6"
        ]
        r2_hw = next(
            item for item in hw_checks if item["hostname"] == "mysid-r2.example"
        )
        self.assertEqual(len(r2_hw["expect_contains"]), 1)
        counters = [
            params for name, params in tasks if name == "rbb_srv6_counter_delta"
        ]
        expected_directions = [
            "tc18_midpoint_egress",
            "tc18_shifted_ingress",
            "tc18_head_egress",
            "tc18_tail_ingress",
        ]
        self.assertEqual(
            [item["direction"] for item in counters[:4]], expected_directions
        )
        self.assertEqual(
            [item["direction"] for item in counters[4:]], expected_directions
        )
        for item in counters[5:]:
            self.assertEqual(item["reference_hostname"], "mysid-r2.example")
            self.assertEqual(
                item["reference_direction"], "tc18_midpoint_egress"
            )
            self.assertEqual(item["min_reference_ratio"], 0.8)

    def test_tc32_and_tc106_use_distinct_exact_drop_counters(self) -> None:
        tc32, tc106 = (self.config.playbooks or [])[-2:]
        tc32_counters = [p for n, p in _tasks(tc32) if n == "rbb_srv6_counter_delta"]
        self.assertEqual({item["direction"] for item in tc32_counters}, {"mysid_drop"})
        self.assertTrue(all(item["min_delta"] == 100 for item in tc32_counters))
        self.assertTrue(
            all(
                "in_srv6_mysid_discards" in item["counter_cmd"]
                for item in tc32_counters
            )
        )

        tc106_counters = [p for n, p in _tasks(tc106) if n == "rbb_srv6_counter_delta"]
        self.assertEqual(
            {item["direction"] for item in tc106_counters},
            {"unknown_drop", "possible_egress"},
        )
        self.assertTrue(
            all(
                item["min_delta"] == 100
                for item in tc106_counters
                if item["direction"] == "unknown_drop"
            )
        )
        no_egress = [
            item
            for item in tc106_counters
            if item["direction"] == "possible_egress"
        ]
        self.assertEqual([item["min_delta"] for item in no_egress], [0, 0])
        self.assertEqual([item["max_delta"] for item in no_egress], [100, 100])
        unknown_check = next(
            params for name, params in _tasks(tc106) if name == "rbb_srv6_verify"
        )
        self.assertEqual(unknown_check["show_cmd"], "fboss2 show mysid")
        self.assertEqual(len(unknown_check["expect_absent"]), 1)

    def test_negative_checks_require_100_percent_loss(self) -> None:
        for playbook in (self.config.playbooks or [])[-2:]:
            validation = next(
                step
                for step in _steps(playbook)
                if step.name == StepName.VALIDATION_STEP
                and "completely dropped" in (step.description or "")
            )
            check = json.loads(validation.input_json)["point_in_time_checks"][0]
            thresholds = json.loads(check["input_json"])["thresholds"]
            self.assertEqual(len(thresholds), 2)
            self.assertTrue(thresholds[0]["expect_packet_loss"])
            threshold = thresholds[1]
            self.assertEqual(threshold["str_value"], "100")
            self.assertFalse(threshold["expect_packet_loss"])
            self.assertEqual(
                threshold["comparison"],
                hc_types.ComparisonType.GREATER_THAN_EQUAL_TO.value,
            )


if __name__ == "__main__":
    unittest.main()
