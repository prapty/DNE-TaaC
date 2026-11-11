"""OSS entrypoint for Phase-2 TC-16/17/18/32/106."""

from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_mysid_test_config import (
    create_rbb_srv6_mysid_test_config,
)

test_config = create_rbb_srv6_mysid_test_config()
