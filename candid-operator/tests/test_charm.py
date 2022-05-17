# Copyright 2022 Canonical Ltd
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import os
import pathlib
import shutil
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from charm import CandidOperatorCharm
from ops.testing import Harness

MINIMAL_CONFIG = {
    'admin-agent-public-key': 'test-admin-public-key',
    'api-macaroon-timeout': '10m',
    'discharge-macaroon-timeout': '20m',
    'discharge-token-timeout': '30m',
    'identity-providers': '''\
- type: static
  name: static
  description: Default identity provider
  require-mfa: true
  users:
    user1:
      name: User One
      email: user1@example.com
      password: password1
      groups:
       - group1
       - group3''',
    'location': 'test-location',
    'private-key': 'test-private-key',
    'public-key': 'test-public-key',
    'rendezvous-timeout': '5m',
    'postgresql-dsn': 'test-postgresql-dsn'
}


class test_process:
    def wait_output(self):
        return '''{
            "private": "generated-private-key",
            "public": "generated-public-key"
        }''', '''{'a'}'''


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.harness = Harness(CandidOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.disable_hooks()
        self.harness.add_oci_resource("candid-image")
        self.harness.begin()

        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        shutil.copytree(os.path.join(self.harness.charm.charm_dir, "templates"),
                        os.path.join(self.tempdir.name, "templates"))
        self.harness.charm.framework.charm_dir = pathlib.Path(self.tempdir.name)

        self.harness.container_pebble_ready('candid')

    def test_on_pebble_ready(self):
        self.harness.update_config(MINIMAL_CONFIG)

        self.harness.update_config({
            'private-key': 'new-private-key',
            'public-key': 'new-public-key'
        })

        container = self.harness.model.unit.get_container("candid")
        # Emit the pebble-ready event for jimm
        self.harness.charm.on.candid_pebble_ready.emit(container)

        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("candid")
        self.assertEqual(
            plan.to_dict(),
            {'services': {
                'candid': {
                    'summary': 'Candid Identity Service',
                    'startup': 'disabled',
                    'override': 'merge',
                    'command': '/root/candidsrv /root/config.yaml',
                    'environment': {
                        'ADMIN_AGENT_PUBLIC_KEY': 'test-admin-public-key',
                        'API_MACAROON_TIMEOUT': '10m',
                        'DISCHARGE_MACAROON_TIMEOUT': '20m',
                        'DISCHARGE_TOKEN_TIMEOUT': '30m',
                        'IDENTITY_PROVIDERS': '''\
- type: static
  name: static
  description: Default identity provider
  require-mfa: true
  users:
    user1:
      name: User One
      email: user1@example.com
      password: password1
      groups:
       - group1
       - group3''',
                        'LOCATION': 'test-location',
                        'LOGGING_CONFIG': 'INFO',
                        'POSTGRESQL_DSN': 'test-postgresql-dsn',
                        'PRIVATE_KEY': 'new-private-key',
                        'PUBLIC_KEY': 'new-public-key',
                        'RENDEZVOUS_TIMEOUT': '5m'
                    }
                }
            }}
        )

        config = container.pull('/root/config.yaml')
        self.assertEqual(textwrap.dedent('''\
                            access-log: /root/logs/access.log
                            auth-username: admin
                            listen-address: :8081
                            max-mgo-sessions: 300
                            request-timeout: 2s
                            resource-path: /root/www
                            storage:
                                type: postgres
                                connection-string: test-postgresql-dsn
                            location: test-location
                            private-key: new-private-key
                            public-key: new-public-key
                            private-addr: localhost
                            admin-agent-private-key: test-admin-public-key
                            identity-providers:
                            - type: static
                              name: static
                              description: Default identity provider
                              require-mfa: true
                              users:
                                user1:
                                  name: User One
                                  email: user1@example.com
                                  password: password1
                                  groups:
                                   - group1
                                   - group3'''
                                         ),
                         config.read()
                         )

    def test_on_config_changed(self):
        self.harness.update_config(MINIMAL_CONFIG)

        container = self.harness.model.unit.get_container("candid")
        self.harness.charm.on.candid_pebble_ready.emit(container)

        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("candid")
        self.assertEqual(
            plan.to_dict(),
            {'services': {
                'candid': {
                    'summary': 'Candid Identity Service',
                    'startup': 'disabled',
                    'override': 'merge',
                    'command': '/root/candidsrv /root/config.yaml',
                    'environment': {
                        'ADMIN_AGENT_PUBLIC_KEY': 'test-admin-public-key',
                        'API_MACAROON_TIMEOUT': '10m',
                        'DISCHARGE_MACAROON_TIMEOUT': '20m',
                        'DISCHARGE_TOKEN_TIMEOUT': '30m',
                        'IDENTITY_PROVIDERS': '''\
- type: static
  name: static
  description: Default identity provider
  require-mfa: true
  users:
    user1:
      name: User One
      email: user1@example.com
      password: password1
      groups:
       - group1
       - group3''',
                        'LOCATION': 'test-location',
                        'LOGGING_CONFIG': 'INFO',
                        'POSTGRESQL_DSN': 'test-postgresql-dsn',
                        'PRIVATE_KEY': 'test-private-key',
                        'PUBLIC_KEY': 'test-public-key',
                        'RENDEZVOUS_TIMEOUT': '5m'
                    }
                }
            }}
        )

        config = container.pull('/root/config.yaml')
        self.assertEqual(textwrap.dedent('''\
                            access-log: /root/logs/access.log
                            auth-username: admin
                            listen-address: :8081
                            max-mgo-sessions: 300
                            request-timeout: 2s
                            resource-path: /root/www
                            storage:
                                type: postgres
                                connection-string: test-postgresql-dsn
                            location: test-location
                            private-key: test-private-key
                            public-key: test-public-key
                            private-addr: localhost
                            admin-agent-private-key: test-admin-public-key
                            identity-providers:
                            - type: static
                              name: static
                              description: Default identity provider
                              require-mfa: true
                              users:
                                user1:
                                  name: User One
                                  email: user1@example.com
                                  password: password1
                                  groups:
                                   - group1
                                   - group3'''),
                         config.read()
                         )

    @patch('ops.model.Container.exec')
    def test_on_leader_elected(self, exec):
        exec.return_value = test_process()

        self.harness.update_config({
            'admin-agent-public-key': 'test-admin-public-key',
            'api-macaroon-timeout': '10m',
            'discharge-macaroon-timeout': '20m',
            'discharge-token-timeout': '30m',
            'identity-providers': 'test-identity-providers',
            'location': 'test-location',
            'rendezvous-timeout': '5m',
            'postgresql-dsn': 'test-postgresql-dsn',
        })

        rel_id = self.harness.add_relation('candid', 'candid')
        self.harness.add_relation_unit(rel_id, 'candid/1')
        self.harness.set_leader(True)

        self.harness.charm.on.leader_elected.emit()

        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("candid")
        self.assertEqual(
            plan.to_dict(),
            {'services': {
                'candid': {
                    'summary': 'Candid Identity Service',
                    'startup': 'disabled',
                    'override': 'merge',
                    'command': '/root/candidsrv /root/config.yaml',
                    'environment': {
                        'ADMIN_AGENT_PUBLIC_KEY': 'test-admin-public-key',
                        'API_MACAROON_TIMEOUT': '10m',
                        'DISCHARGE_MACAROON_TIMEOUT': '20m',
                        'DISCHARGE_TOKEN_TIMEOUT': '30m',
                        'IDENTITY_PROVIDERS': 'test-identity-providers',
                        'LOCATION': 'test-location',
                        'LOGGING_CONFIG': 'INFO',
                        'POSTGRESQL_DSN': 'test-postgresql-dsn',
                        'PRIVATE_KEY': 'generated-private-key',
                        'PUBLIC_KEY': 'generated-public-key',
                        'RENDEZVOUS_TIMEOUT': '5m'
                    }
                }
            }}
        )

        self.assertEqual(self.harness.get_relation_data(rel_id, "candid"), {
            'private-key': 'generated-private-key',
            'public-key': 'generated-public-key'
        })

    def test_keys_from_relation_data(self):
        self.harness.update_config({
            'no-proxy': '192.168.0.1'
        })

        rel_id = self.harness.add_relation('candid', 'candid')
        self.harness.add_relation_unit(rel_id, 'candid/1')

        self.harness.set_leader(False)
        self.harness.update_relation_data(rel_id, 'candid', {
            'private-key': 'generated-private-key',
            'public-key': 'generated-public-key'
        })
        self.harness.update_relation_data(rel_id, 'candid/1', {
            'private-address': '192.168.0.2',
        })

        container = self.harness.model.unit.get_container("candid")
        self.harness.charm.on.candid_pebble_ready.emit(container)

        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("candid")
        self.assertEqual(
            plan.to_dict(),
            {'services': {
                'candid': {
                    'summary': 'Candid Identity Service',
                    'startup': 'disabled',
                    'override': 'merge',
                    'command': '/root/candidsrv /root/config.yaml',
                    'environment': {
                        'API_MACAROON_TIMEOUT': '48h',
                        'DISCHARGE_MACAROON_TIMEOUT': '48h',
                        'DISCHARGE_TOKEN_TIMEOUT': '48h',
                        'LOGGING_CONFIG': 'INFO',
                        'NO_PROXY': '192.168.0.1,192.168.0.2',
                        'PRIVATE_KEY': 'generated-private-key',
                        'PUBLIC_KEY': 'generated-public-key',
                        'RENDEZVOUS_TIMEOUT': '10m'
                    }
                }
            }}
        )
