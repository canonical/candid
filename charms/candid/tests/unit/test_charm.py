# Copyright 2022 Ales Stimec
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

from ops.testing import Harness

from charm import CandidCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(CandidCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_website_relation_joined(self):
        id = self.harness.add_relation("website", "apache2")
        self.harness.add_relation_unit(id, "apache2/0")
        data = self.harness.get_relation_data(id, self.harness.charm.unit.name)
        self.assertTrue(data)
        self.assertEqual(data["port"], "8081")
