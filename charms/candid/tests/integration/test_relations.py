#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import integration.utils as utils
import pytest
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)


APP_NAME = "candid"
PG_NAME = "postgresql"
HA_NAME = "haproxy"


@pytest.mark.abort_on_fail
@pytest.mark.usefixtures("deploy_built_bundle")
class TestRelations:
    async def test_no_postgresql_relation(self, ops_test: OpsTest):
        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked")

        candid_unit = await utils.get_unit_by_name("candid", "0", ops_test.model.units)
        assert candid_unit.workload_status == "blocked"
        assert candid_unit.workload_status_message == "Waiting for postgres relation."

    async def test_add_postgresql_relation(self, ops_test: OpsTest):
        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(apps=[APP_NAME, PG_NAME])

        await ops_test.model.add_relation(APP_NAME, "{}:db".format(PG_NAME))

        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active")

        candid_unit = await utils.get_unit_by_name("candid", "0", ops_test.model.units)
        assert candid_unit.workload_status == "active"
        assert candid_unit.workload_status_message == "Ready"

    async def test_add_haproxy_relation(self, ops_test: OpsTest):
        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(apps=[APP_NAME, HA_NAME])

        await ops_test.model.add_relation(APP_NAME, HA_NAME)

        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active")

        candid_unit = await utils.get_unit_by_name("candid", "0", ops_test.model.units)
        assert candid_unit.workload_status == "active"
        assert candid_unit.workload_status_message == "Ready"
