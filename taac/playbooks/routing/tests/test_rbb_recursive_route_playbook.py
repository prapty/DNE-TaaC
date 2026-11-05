# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Structure tests for the Phase-2 TC-01 recursive-route playbook."""

import json
import unittest

from taac.playbooks.routing.factories.qual_rbb.rbb_recursive_route_playbook import (
    create_rbb_recursive_route_playbook,
)
from taac.test_as_a_config import types as taac_types
from taac.testconfigs.routing.util.bgp_rbb_recursive_route_profiles import (
    RECURSIVE_ROUTE_PROFILE,
)


def _payload(step):
    task = json.loads(step.input_json or "{}")['task']
    return task["task_name"], json.loads(task["params"]["json_params"])


class RbbRecursiveRoutePlaybookTest(unittest.TestCase):
    def test_playbook_runs_full_reversible_lifecycle(self) -> None:
        playbook = create_rbb_recursive_route_playbook(
            RECURSIVE_ROUTE_PROFILE,
            r1_hostname="r1.example",
            r2_hostname="r2.example",
        )
        tasks = [
            _payload(step)
            for stage in playbook.stages
            for step in stage.steps
            if step.name == taac_types.StepName.RUN_TASK_STEP
        ]

        self.assertEqual(
            [params["action"] for _, params in tasks],
            ["precheck", "install", "verify", "cleanup"],
        )
        self.assertTrue(all(name == "rbb_recursive_route" for name, _ in tasks))
        self.assertTrue(
            all(params["head_hostname"] == "r1.example" for _, params in tasks)
        )
        self.assertTrue(
            all(params["tail_hostname"] == "r2.example" for _, params in tasks)
        )
        self.assertIn("[FULL]", playbook.description)
        self.assertEqual(playbook.device_regexes, ["^r1\\.example$"])
        self.assertIsNone(playbook.traffic_items_to_start)

        cleanup_name, cleanup = _payload(playbook.cleanup_steps[0])
        self.assertEqual(cleanup_name, "rbb_recursive_route")
        self.assertEqual(cleanup["action"], "cleanup")

    def test_rejects_missing_or_duplicate_hosts(self) -> None:
        with self.assertRaisesRegex(ValueError, "distinct"):
            create_rbb_recursive_route_playbook(
                RECURSIVE_ROUTE_PROFILE,
                r1_hostname="same.example",
                r2_hostname="same.example",
            )


if __name__ == "__main__":
    unittest.main()
