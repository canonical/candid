#!/usr/bin/env python3
# Copyright 2022 Ales Stimec
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""

import logging
import subprocess
from collections.abc import MutableMapping

import pgsql
from charms.operator_libs_linux.v1.snap import Snap, SnapCache, SnapError
from ops.charm import CharmBase, StartEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
    WaitingStatus,
)

logger = logging.getLogger(__name__)

SNAP_NAME = "candid"

REQUIRED_SETTINGS = [
    "admin-agent-public-key",
    "api-macaroon-timeout",
    "discharge-macaroon-timeout",
    "discharge-token-timeout",
    "identity-providers",
    "location",
    "private-key",
    "public-key",
    "rendezvous-timeout",
]


class CandidCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    @property
    def snap(self) -> Snap:
        """Retrieves snap from the snap cache"""
        return SnapCache().get(SNAP_NAME)

    @property
    def snap_installed(self) -> bool:
        """Reports if the Candid snap is installed."""
        return self.snap.present

    @property
    def snap_running(self):
        """Reports if the 'candidsrv' snap daemon is running."""
        return self.snap.services["candidsrv"]["active"]

    def __init__(self, *args):
        super().__init__(*args)

        # Hooks
        self.framework.observe(self.on.install, self._install)
        self.framework.observe(self.on.start, self._start)
        self.framework.observe(self.on.config_changed, self._config_changed)
        self.framework.observe(
            self.on.website_relation_joined, self._on_website_relation_joined
        )

        # Database
        self.db = pgsql.PostgreSQLClient(self, "postgres")
        self.framework.observe(
            self.db.on.database_relation_joined,
            self._on_database_relation_joined,
        )
        self.framework.observe(
            self.db.on.master_changed, self._on_master_changed
        )

        self._stored.set_default(db_uri=None)

    ###################
    # LIFECYCLE HOOKS #
    ###################
    def _install(self, _):
        """
        Install candid snap
        """
        self.set_status_and_log("Installing snap", WaitingStatus)
        self._install_snap()
        if self.snap_installed:
            self.set_status_and_log("Snap installed", WaitingStatus)

    def _start(self, event: StartEvent):
        """
        Starts candidsrv service
        """
        if not self._check_config(event):
            event.defer()
            return

        self.set_status_and_log("Starting candid", WaitingStatus)
        self.snap.start(["candidsrv"])
        if self.snap_running:
            self.set_status_and_log("Ready", ActiveStatus)

    def _config_changed(self, event: StartEvent):
        """
        Updates snap internal configuration.
        """
        self._update_config_and_restart(event)

    def _update_config_and_restart(self, event):
        if not self._check_config(event):
            return

        config_values = {
            key: value for key, value in self.config.items() if value
        }
        if self._stored.db_uri:
            config_values["storage"] = {
                "type": "postgres",
                "connection-string": self._stored.db_uri,
            }
        else:
            logging.info("db_uri not stored")

        logging.info("setting config values {}".format(config_values))

        config_values = flatten_dict(config_values)
        config_values = {
            "candid.{}".format(key): value
            for key, value in config_values.items()
            if value
        }
        try:
            self.snap.set(config_values)
        except Exception as e:
            logging.error(
                "error setting snap configuration values: {}".format(e)
            )
        self.set_status_and_log("Restarting.", WaitingStatus)

        if self.snap_running:
            self.snap.restart(["candidsrv"])
        else:
            self.snap.start(services=["candidsrv"])

        if self.snap_running:
            self.set_status_and_log("Ready", ActiveStatus)

    def _check_config(self, event) -> bool:
        """
        Checks if required config is set and relations added.
        """
        if not self.snap_installed:
            # TODO: We need error status, how?
            self.set_status_and_log("Snap not installed", MaintenanceStatus)
            return False

        if self.model.get_relation(self.db.relation_name) is None:
            self.set_status_and_log(
                "Waiting for postgres relation.", BlockedStatus
            )
            return False

        if self._stored.db_uri is None:
            self.set_status_and_log(
                "Waiting for postgres connection string", WaitingStatus
            )
            return False

        for setting in REQUIRED_SETTINGS:
            if not self.config.get(setting, ""):
                self.unit.status = BlockedStatus(
                    "{} configuration value not set".format(setting),
                )
                return False

        return True

    def set_status_and_log(self, msg, status) -> None:
        """
        A simple wrapper to log and set unit status simultaneously.
        """
        logging.info(msg)
        self.unit.status = status(msg)

    ####################
    # WEBSITE RELATION #
    ####################
    def _on_website_relation_joined(self, event):
        """Connect a website relation."""
        event.relation.data[self.unit]["port"] = "8081"

    #####################
    # DATABASE RELATION #
    #####################
    def _on_database_relation_joined(
        self, event: pgsql.DatabaseRelationJoinedEvent
    ) -> None:
        """
        Handles determining if the database has finished setup, once setup is complete
        a master/standby may join / change in consequent events.
        """
        logging.info("(postgresql) RELATION_JOINED event fired.")

        if self.model.unit.is_leader():
            event.database = "candid"
        elif event.database != "candid":
            event.defer()

    def _on_master_changed(self, event: pgsql.MasterChangedEvent) -> None:
        """
        Handles master units of postgres joining / changing.
        The internal snap configuration is updated to reflect this.
        """
        logging.info("(postgresql) MASTER_CHANGED event fired.")

        if event.database != "candid":
            logging.info("Database setup not complete yet, returning.")
            return

        self.set_status_and_log(
            "Updating database configuration...", WaitingStatus
        )

        uri = event.master.uri
        if not uri:
            uri = ""
        logging.info("database uri {}".format(uri))

        self._stored.db_uri = (
            None if event.master is None else event.master.uri
        )
        self._update_config_and_restart(event)

    #############
    # UTILITIES #
    #############
    def _install_snap(self) -> None:
        """
        Installs the Candid snap.
        """
        resource_path = self.model.resources.fetch("candid")
        _cmd = [
            "snap",
            "install",
            resource_path,
            "--classic",
            "--dangerous",
        ]
        try:
            logging.info("Attempting to install candid snap...")
            subprocess.check_output(
                _cmd, universal_newlines=True
            ).splitlines()[0]

            if self.snap.present:
                logging.info("Snap: %s installed!", self.snap.name)
            else:
                raise SnapError(
                    "Could not find livepatch snap, TODO make error better"
                )
        except subprocess.CalledProcessError as e:
            raise SnapError(
                "Could not install snap {}: {}".format(resource_path, e.output)
            )


# flatten_dict copied from ops.model
def flatten_dict(
    input: dict, parent_key: str = None, output: dict = None
) -> dict:
    """Turn a nested dictionary into a flattened dictionary, using '.' as a key separator.
    This is used to allow nested dictionaries to be translated into the dotted format required by
    the Juju `action-set` hook tool in order to set nested data on an action.
    Additionally, this method performs some validation on keys to ensure they only use permitted
    characters.
    Example::
        >>> test_dict = {'a': {'b': 1, 'c': 2}}
        >>> _format_action_result_dict(test_dict)
        {'a.b': 1, 'a.c': 2}
    Arguments:
        input: The dictionary to flatten
        parent_key: The string to prepend to dictionary's keys
        output: The current dictionary to be returned, which may or may not yet be completely flat
    Returns:
        A flattened dictionary with validated keys
    Raises:
        ValueError: if the dict is passed with a mix of dotted/non-dotted keys that expand out to
            result in duplicate keys. For example: {'a': {'b': 1}, 'a.b': 2}. Also raised if a dict
            is passed with a key that fails to meet the format requirements.
    """
    if output is None:
        output = {}
    for key, value in input.items():
        if parent_key:
            key = "{}.{}".format(parent_key, key)
        if isinstance(value, MutableMapping):
            output = flatten_dict(value, key, output)
        elif key in output:
            raise ValueError(
                "duplicate key detected in dictionary passed to 'action-set': {!r}".format(
                    key
                )
            )
        else:
            output[key] = value
    return output


if __name__ == "__main__":
    main(CandidCharm)
