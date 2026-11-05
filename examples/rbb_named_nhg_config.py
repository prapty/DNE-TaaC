# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Entry point for the device-only Phase-2 route lifecycle suite.

Run through ``scripts/run-rbb-srv6.sh --suite named-nhg-lifecycle``. TC-01
originates a temporary iBGP service prefix and proves recursive resolution
through the remote loopback learned by Open/R. TC-02 programs and verifies an
exact named NHG/NHE plus route. TC-03 overlays that OpenR loopback with a
better-distance TE_AGENT SRv6 NHG route and proves the service prefix follows
the new winner. TC-04 binds the load-bearing prefix directly to the SRv6 NHG.
TC-06 and TC-07 run only on FBOSS versions that retain missing-NHG forward
references; versions that reject the reference report those playbooks as
SKIPPED.
"""

from taac.testconfigs.routing.factories.qual_rbb.rbb_named_nhg_test_config import (
    create_rbb_named_nhg_test_config,
)

test_config = create_rbb_named_nhg_test_config()
