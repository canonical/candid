#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""

import base64
import binascii
import functools
import json
import logging
import os

import yaml
from charms.nginx_ingress_integrator.v0.ingress import IngressRequires
from jinja2 import Environment, FileSystemLoader
from ops import pebble
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus


class IdentityProvidersParseError(Exception):
    """Error parsing identity provider configuration."""
    pass


logger = logging.getLogger(__name__)

WORKLOAD_CONTAINER = 'candid'

REQUIRED_SETTINGS = [
    'ADMIN_AGENT_PUBLIC_KEY',
    'API_MACAROON_TIMEOUT',
    'DISCHARGE_MACAROON_TIMEOUT',
    'DISCHARGE_TOKEN_TIMEOUT',
    'IDENTITY_PROVIDERS',
    'LOCATION',
    'PRIVATE_KEY',
    'PUBLIC_KEY',
    'RENDEZVOUS_TIMEOUT',
    'POSTGRESQL_DSN'
]


def log_event_handler(method):
    @functools.wraps(method)
    def decorated(self, event):
        logger.debug('running {}'.format(method.__name__))
        try:
            return method(self, event)
        finally:
            logger.debug('completed {}'.format(method.__name__))

    return decorated


class CandidOperatorCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.candid_pebble_ready, self._on_candid_pebble_ready)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.update_status, self._on_update_status)
        self.framework.observe(self.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.on.candid_relation_changed, self._on_candid_relation_changed)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.website_relation_joined, self._on_website_relation_joined)
        hostname = self.config.get('location', '').lstrip('https://')
        self.ingress = IngressRequires(self, {
            "service-hostname": hostname,
            "service-name": self.app.name,
            "service-port": 8081
        })
        self._config_filename = "/root/config.yaml"

    @log_event_handler
    def _on_candid_pebble_ready(self, event):
        self._on_config_changed(event)

    @log_event_handler
    def _on_config_changed(self, event):
        self._update_workload({}, event)

    @log_event_handler
    def _on_update_status(self, _):
        '''Update the status of the charm.'''
        self._ready()

    @log_event_handler
    def _on_website_relation_joined(self, event):
        '''Connect a website relation.'''
        event.relation.data[self.unit]['port'] = '8081'

    @log_event_handler
    def _on_start(self, _):
        '''Start Candid.'''
        container = self.unit.get_container(WORKLOAD_CONTAINER)
        if container.can_connect():
            plan = container.get_plan()
            if 'candid' not in plan.services:
                self.unit.status = BlockedStatus(
                    'waiting for configuration',
                )
                return
            env_vars = plan.services.get('candid').environment
            for setting in REQUIRED_SETTINGS:
                if not env_vars.get(setting, ''):
                    self.unit.status = BlockedStatus(
                        '{} configuration value not set'.format(setting),
                    )
                    return False
            container.start('candid')

    @log_event_handler
    def _on_stop(self, _):
        '''Stop Candid.'''
        container = self.unit.get_container(WORKLOAD_CONTAINER)
        if self._ready() and container.can_connect():
            container.stop()
            self.unit.status = WaitingStatus('stopped')

    @log_event_handler
    def _on_leader_elected(self, event):
        '''Elected leader generates the keypair to be used
        by all units.'''
        if not self.unit.is_leader():
            return

        candid_relation = self.model.get_relation("candid")
        if not candid_relation:
            return

        if 'public-key' in candid_relation.data[self.app]:
            # if public and private keys are already set
            # there is nothing to do.
            return

        key = self._generate_keypair(event)
        candid_relation.data[self.app].update({'public-key': key['public']})
        candid_relation.data[self.app].update({'private-key': key['private']})

        self._update_workload({}, event)

    def _on_candid_relation_changed(self, event):
        data = event.relation.data[event.app]
        if data['public-key'] and data['private-key']:
            # if public and private keys are already set
            # there is nothing to do.
            return
        self._update_workload({}, event)

    def _update_workload(self, envdata: dict, event):
        '''' Update workload with all available configuration
        data. '''

        hostname = self.config.get('location', '').lstrip('https://')
        self.ingress.update_config({"service-hostname": hostname})

        container = self.unit.get_container(WORKLOAD_CONTAINER)

        private_key = self.config.get('private-key', '')
        public_key = self.config.get('public-key', '')

        candid_relation = self.model.get_relation("candid")
        if candid_relation:
            private_key = candid_relation.data[self.app].get('private-key', '')
            public_key = candid_relation.data[self.app].get('public-key', '')
            print('public {} private {}'.format(public_key, private_key))

        config_values = {
            'ADMIN_AGENT_PUBLIC_KEY': self.config.get('admin-agent-public-key', ''),
            'API_MACAROON_TIMEOUT': self.config.get('api-macaroon-timeout', ''),
            'DISCHARGE_MACAROON_TIMEOUT': self.config.get('discharge-macaroon-timeout', ''),
            'DISCHARGE_TOKEN_TIMEOUT': self.config.get('discharge-token-timeout', ''),
            'ENABLE_EMAIL_LOGIN': self.config.get('enable-email-login', False),
            'HTTP_PROXY': self.config.get('http-proxy'),
            'LOCATION': self.config.get('location'),
            'LOGGING_CONFIG': self.config.get('logging-config'),
            'IDENTITY_PROVIDERS': self.config.get('identity-providers'),
            'NO_PROXY': self.config.get('no-proxy', ''),
            'PRIVATE_KEY': private_key,
            'PUBLIC_KEY': public_key,
            'REDIRECT_LOGIN_TRUSTED_URLS': self.config.get('redirect-login-trusted-urls', ''),
            'REDIRECT_LOGIN_TRUSTED_DOMAINS': self.config.get(
                'redirect-login-trusted-domains',
                ''
            ),
            'RENDEZVOUS_TIMEOUT': self.config.get('rendezvous-timeout'),
            'SKIP_LOCATION_FOR_COOKIE_PATHS': self.config.get(
                'skip-location-for-cookie-paths',
                False
            ),
            'MFA_RP_DISPLAY_NAME': self.config.get('mfa-rp-display-name', ''),
            'MFA_RP_ID': self.config.get('mfa-rp-id', ''),
            'MFA_RP_ORIGIN': self.config.get('mfa-rp-origin', ''),
            'POSTGRESQL_DSN': self.config.get('postgresql-dsn', ''),
        }

        # apply specified environment data
        config_values.update(envdata)
        # remove empty configuration values
        config_values = {key: value for key, value in config_values.items() if value}

        # if private and public keys are not set, then
        # we check the candid relation data if the leader
        # already generated a key
        candid_relation = self.model.get_relation('candid')
        if 'PUBLIC_KEY' not in config_values and candid_relation:
            config_values['PUBLIC_KEY'] = candid_relation.data[self.app].get('public-key', '')
        if 'PRIVATE_KEY' not in config_values and candid_relation:
            config_values['PRIVATE_KEY'] = candid_relation.data[self.app].get('private-key', '')

        # extend no-proxy to include all candid units.
        no_proxy = []
        if 'NO_PROXY' in config_values:
            no_proxy = [config_values['NO_PROXY']]

        if candid_relation:
            for unit in candid_relation.units:
                if unit not in candid_relation.data:
                    continue
                if 'private-address' in candid_relation.data[unit]:
                    no_proxy.append(candid_relation.data[unit].get('private-address'))
        if no_proxy:
            config_values['NO_PROXY'] = ','.join(no_proxy)

        if container.can_connect():
            # first update configuration values
            pebble_layer = {
                'summary': 'Candid Identity Service',
                'description': 'Pebble config layer for candid',
                'services': {
                    'candid': {
                        'override': 'merge',
                        'summary': 'Candid Identity Service',
                        'command': '/root/candidsrv /root/config.yaml',
                        'startup': 'disabled',
                        'environment': config_values,
                    }
                },
                'checks': {
                    'candid-check': {
                        'override': 'replace',
                        'period': '1m',
                        'http': {
                            'url': 'http://localhost:8081/debug/status'
                        }
                    }
                }
            }
            container.add_layer('candid', pebble_layer, combine=True)

            # fetch the current plan
            current_plan = container.get_plan()

            # render the config.yaml
            args = current_plan.services.get('candid').environment

            config = self._render_template('config.yaml.tmpl', **args)
            if not container.exists(os.path.dirname(self._config_filename)):
                container.make_dir(os.path.dirname(self._config_filename))
            container.push(self._config_filename, config)

            if self._ready():
                if container.get_service('candid').is_running():
                    container.replan()
                else:
                    container.start('candid')
        else:
            logger.info('workload container not ready - defering')
            event.defer()

    def _ready(self):
        container = self.unit.get_container(WORKLOAD_CONTAINER)

        if container.can_connect():
            plan = container.get_plan()
            if plan.services.get('candid') is None:
                logger.error('waiting for service')
                self.unit.status = WaitingStatus('waiting for service')
                return False

            env_vars = plan.services.get('candid').environment

            for setting in REQUIRED_SETTINGS:
                if not env_vars.get(setting, ''):
                    self.unit.status = BlockedStatus(
                        '{} configuration value not set'.format(setting),
                    )
                    return False

            if container.get_service('candid').is_running():
                self.unit.status = ActiveStatus('running')
            return True
        else:
            logger.error('cannot connect to workload container')
            self.unit.status = WaitingStatus('waiting for candid workload')
            return False

    def _render_template(self, name, **kwargs):
        """Load the template with the given name."""
        loader = FileSystemLoader(os.path.join(self.charm_dir, 'templates'))
        env = Environment(loader=loader)
        return env.get_template(name).render(**kwargs)

    def _generate_keypair(self, event):
        """ Create a default keypair shared by all units in the application,
            if a keypair is not explicitely configured. """
        container = self.unit.get_container(WORKLOAD_CONTAINER)

        if container.can_connect():
            process = container.exec(['/root/bakery-keygen'])

            try:
                stdout, _ = process.wait_output()
                return json.loads(stdout)
            except pebble.ExecError as e:
                logger.error('error generating keypair %d. Stderr:', e.exit_code)
                for line in e.stderr.splitlines():
                    logger.error('    %s', line)
        else:
            logger.info('workload container not ready - defering')
            event.defer()

    def _parse_identity_providers(self, idps):
        """ parse the identity-providers configuration option. """
        b64err = None
        try:
            idps = base64.b64decode(idps, validate=True)
        except binascii.Error as e:
            # Be tolerant of non-base64 values, to facilitate upgrades from
            # earlier charm versions.
            b64err = e
        try:
            return yaml.safe_load(idps)
        except yaml.YAMLError as e:
            msg = "error parsing identity-providers: {}".format(e)
            if b64err:
                msg += ", {}".format(b64err)
            raise IdentityProvidersParseError()


if __name__ == "__main__":
    main(CandidOperatorCharm)
