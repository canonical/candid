# Copyright 2021 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Representations of the system's Snaps, and abstractions around managing them.

The `snap` module provides convenience methods for listing, installing, refreshing, and removing
Snap packages, in addition to setting and getting configuration options for them.

In the `snap` module, `SnapCache` creates a dict-like mapping of `Snap` objects at when
instantiated. Installed snaps are fully populated, and available snaps are lazily-loaded upon
request. This module relies on an installed and running `snapd` daemon to perform operations over
the `snapd` HTTP API.

`SnapCache` objects can be used to install or modify Snap packages by name in a manner similar to
using the `snap` command from the commandline.

An example of adding Juju to the system with `SnapCache` and setting a config value:

```python
try:
    cache = snap.SnapCache()
    juju = cache["juju"]

    if not juju.present:
        juju.ensure(snap.SnapState.Latest, channel="beta")
        juju.set({"some.key": "value", "some.key2": "value2"})
except snap.SnapError as e:
    logger.error("An exception occurred when installing charmcraft. Reason: %s", e.message)
```

In addition, the `snap` module provides "bare" methods which can act on Snap packages as
simple function calls. :meth:`add`, :meth:`remove`, and :meth:`ensure` are provided, as
well as :meth:`add_local` for installing directly from a local `.snap` file. These return
`Snap` objects.

As an example of installing several Snaps and checking details:

```python
try:
    nextcloud, charmcraft = snap.add(["nextcloud", "charmcraft"])
    if nextcloud.get("mode") != "production":
        nextcloud.set({"mode": "production"})
except snap.SnapError as e:
    logger.error("An exception occurred when installing snaps. Reason: %s" % e.message)
```
"""

import http.client
import json
import logging
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from enum import Enum
from subprocess import CalledProcessError, CompletedProcess
from typing import Any, Dict, Iterable, List, Optional, Union

logger = logging.getLogger(__name__)

# The unique Charmhub library identifier, never change it
LIBID = "05394e5893f94f2d90feb7cbe6b633cd"

# Increment this major API version when introducing breaking changes
LIBAPI = 1

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 4


def _cache_init(func):
    def inner(*args, **kwargs):
        if _Cache.cache is None:
            _Cache.cache = SnapCache()
        return func(*args, **kwargs)

    return inner


# recursive hints seems to error out pytest
JSONType = Union[Dict[str, Any], List[Any], str, int, float]


class SnapService:
    """Data wrapper for snap services."""

    def __init__(
        self,
        daemon: Optional[str] = None,
        daemon_scope: Optional[str] = None,
        enabled: bool = False,
        active: bool = False,
        activators: List[str] = [],
        **kwargs
    ):
        self.daemon = daemon
        self.daemon_scope = kwargs.get("daemon-scope", None) or daemon_scope
        self.enabled = enabled
        self.active = active
        self.activators = activators

    def as_dict(self) -> Dict:
        """Returns instance representation as dict."""
        return {
            "daemon": self.daemon,
            "daemon_scope": self.daemon_scope,
            "enabled": self.enabled,
            "active": self.active,
            "activators": self.activators,
        }


class MetaCache(type):
    """MetaCache class used for initialising the snap cache."""

    @property
    def cache(cls) -> "SnapCache":
        """Property for returning the snap cache."""
        return cls._cache

    @cache.setter
    def cache(cls, cache: "SnapCache") -> None:
        """Setter for the snap cache."""
        cls._cache = cache

    def __getitem__(cls, name) -> "Snap":
        """Snap cache getter."""
        return cls._cache[name]


class _Cache(object, metaclass=MetaCache):
    _cache = None


class Error(Exception):
    """Base class of most errors raised by this library."""

    def __repr__(self):
        """String representation of the Error class."""
        return "<{}.{} {}>".format(
            type(self).__module__, type(self).__name__, self.args
        )

    @property
    def name(self):
        """Return a string representation of the model plus class."""
        return "<{}.{}>".format(type(self).__module__, type(self).__name__)

    @property
    def message(self):
        """Return the message passed as an argument."""
        return self.args[0]


class SnapAPIError(Error):
    """Raised when an HTTP API error occurs talking to the Snapd server."""

    def __init__(self, body: Dict, code: int, status: str, message: str):
        """This shouldn't be instantiated directly."""
        super().__init__(message)  # Makes str(e) return message
        self.body = body
        self.code = code
        self.status = status
        self._message = message

    def __repr__(self):
        """String representation of the SnapAPIError class."""
        return "APIError({!r}, {!r}, {!r}, {!r})".format(
            self.body, self.code, self.status, self._message
        )


class SnapState(Enum):
    """The state of a snap on the system or in the cache."""

    Present = "present"
    Absent = "absent"
    Latest = "latest"
    Available = "available"


class SnapError(Error):
    """Raised when there's an error running snap control commands."""


class SnapNotFoundError(Error):
    """Raised when a requested snap is not known to the system."""


class Snap(object):
    """Represents a snap package and its properties.

    `Snap` exposes the following properties about a snap:
      - name: the name of the snap
      - state: a `SnapState` representation of its install status
      - channel: "stable", "candidate", "beta", and "edge" are common
      - revision: a string representing the snap's revision
      - confinement: "classic" or "strict"
    """

    def __init__(
        self,
        name,
        state: SnapState,
        channel: str,
        revision: str,
        confinement: str,
        apps: Optional[List[Dict[str, str]]] = None,
        cohort: Optional[str] = "",
    ) -> None:
        self._name = name
        self._state = state
        self._channel = channel
        self._revision = revision
        self._confinement = confinement
        self._cohort = cohort
        self._apps = apps or []
        self._snap_client = SnapClient()

    def __eq__(self, other) -> bool:
        """Equality for comparison."""
        return isinstance(other, self.__class__) and (
            self._name,
            self._revision,
        ) == (other._name, other._revision)

    def __hash__(self):
        """A basic hash so this class can be used in Mappings and dicts."""
        return hash((self._name, self._revision))

    def __repr__(self):
        """A representation of the snap."""
        return "<{}.{}: {}>".format(
            self.__module__, self.__class__.__name__, self.__dict__
        )

    def __str__(self):
        """A human-readable representation of the snap."""
        return "<{}: {}-{}.{} -- {}>".format(
            self.__class__.__name__,
            self._name,
            self._revision,
            self._channel,
            str(self._state),
        )

    def _snap(
        self, command: str, optargs: Optional[Iterable[str]] = None
    ) -> str:
        """Perform a snap operation.

        Args:
          command: the snap command to execute
          optargs: an (optional) list of additional arguments to pass,
            commonly confinement or channel

        Raises:
          SnapError if there is a problem encountered
        """
        optargs = optargs or []
        _cmd = ["snap", command, self._name, *optargs]
        try:
            return subprocess.check_output(_cmd, universal_newlines=True)
        except CalledProcessError as e:
            raise SnapError(
                "Snap: {!r}; command {!r} failed with output = {!r}".format(
                    self._name, _cmd, e.output
                )
            )

    def _snap_daemons(
        self,
        command: List[str],
        services: Optional[List[str]] = None,
    ) -> CompletedProcess:

        if services:
            # an attempt to keep the command constrained to the snap instance's services
            services = [
                "{}.{}".format(self._name, service) for service in services
            ]
        else:
            services = [self._name]

        _cmd = ["snap", *command, *services]

        try:
            return subprocess.run(
                _cmd, universal_newlines=True, check=True, capture_output=True
            )
        except CalledProcessError as e:
            raise SnapError(
                "Could not {} for snap [{}]: {}".format(
                    _cmd, self._name, e.stderr
                )
            )

    def get(self, key) -> str:
        """Gets a snap configuration value.

        Args:
            key: the key to retrieve
        """
        return self._snap("get", [key]).strip()

    def set(self, config: Dict) -> str:
        """Sets a snap configuration value.

        Args:
           config: a dictionary containing keys and values specifying the config to set.
        """
        args = ['{}="{}"'.format(key, val) for key, val in config.items()]

        return self._snap("set", [*args])

    def unset(self, key) -> str:
        """Unsets a snap configuration value.

        Args:
            key: the key to unset
        """
        return self._snap("unset", [key])

    def start(
        self,
        services: Optional[List[str]] = None,
        enable: Optional[bool] = False,
    ) -> None:
        """Starts a snap's services.

        Args:
            services (list): (optional) list of individual snap services to start (otherwise all)
            enable (bool): (optional) flag to enable snap services on start. Default `false`
        """
        args = ["start", "--enable"] if enable else ["start"]
        self._snap_daemons(args, services)

    def stop(
        self,
        services: Optional[List[str]] = None,
        disable: Optional[bool] = False,
    ) -> None:
        """Stops a snap's services.

        Args:
            services (list): (optional) list of individual snap services to stop (otherwise all)
            disable (bool): (optional) flag to disable snap services on stop. Default `False`
        """
        args = ["stop", "--disable"] if disable else ["stop"]
        self._snap_daemons(args, services)

    def logs(
        self,
        services: Optional[List[str]] = None,
        num_lines: Optional[int] = 10,
    ) -> str:
        """Shows a snap services' logs.

        Args:
            services (list): (optional) list of individual snap services to show logs from
                (otherwise all)
            num_lines (int): (optional) integer number of log lines to return. Default `10`
        """
        args = ["logs", "-n={}".format(num_lines)] if num_lines else ["logs"]
        return self._snap_daemons(args, services).stdout

    def restart(
        self,
        services: Optional[List[str]] = None,
        reload: Optional[bool] = False,
    ) -> None:
        """Restarts a snap's services.

        Args:
            services (list): (optional) list of individual snap services to show logs from.
                (otherwise all)
            reload (bool): (optional) flag to use the service reload command, if available.
                Default `False`
        """
        args = ["restart", "--reload"] if reload else ["restart"]
        self._snap_daemons(args, services)

    def _install(
        self, channel: Optional[str] = "", cohort: Optional[str] = ""
    ) -> None:
        """Add a snap to the system.

        Args:
          channel: the channel to install from
          cohort: optional, the key of a cohort that this snap belongs to
        """
        cohort = cohort or self._cohort

        args = []
        if self.confinement == "classic":
            args.append("--classic")
        if channel:
            args.append('--channel="{}"'.format(channel))
        if cohort:
            args.append('--cohort="{}"'.format(cohort))

        self._snap("install", args)

    def _refresh(
        self,
        channel: Optional[str] = "",
        cohort: Optional[str] = "",
        leave_cohort: Optional[bool] = False,
    ) -> None:
        """Refresh a snap.

        Args:
          channel: the channel to install from
          cohort: optionally, specify a cohort.
          leave_cohort: leave the current cohort.
        """
        channel = '--channel="{}"'.format(channel) if channel else ""
        args = [channel]

        if not cohort:
            cohort = self._cohort

        if leave_cohort:
            self._cohort = ""
            args.append("--leave-cohort")
        elif cohort:
            args.append('--cohort="{}"'.format(cohort))

        self._snap("refresh", args)

    def _remove(self) -> str:
        """Removes a snap from the system."""
        return self._snap("remove")

    @property
    def name(self) -> str:
        """Returns the name of the snap."""
        return self._name

    def ensure(
        self,
        state: SnapState,
        classic: Optional[bool] = False,
        channel: Optional[str] = "",
        cohort: Optional[str] = "",
    ):
        """Ensures that a snap is in a given state.

        Args:
          state: a `SnapState` to reconcile to.
          classic: an (Optional) boolean indicating whether classic confinement should be used
          channel: the channel to install from
          cohort: optional. Specify the key of a snap cohort.

        Raises:
          SnapError if an error is encountered
        """
        self._confinement = (
            "classic" if classic or self._confinement == "classic" else ""
        )

        if state not in (SnapState.Present, SnapState.Latest):
            # We are attempting to remove this snap.
            if self._state in (SnapState.Present, SnapState.Latest):
                # The snap is installed, so we run _remove.
                self._remove()
            else:
                # The snap is not installed -- no need to do anything.
                pass
        else:
            # We are installing or refreshing a snap.
            if self._state not in (SnapState.Present, SnapState.Latest):
                # The snap is not installed, so we install it.
                self._install(channel, cohort)
            else:
                # The snap is installed, but we are changing it (e.g., switching channels).
                self._refresh(channel, cohort)

        self._update_snap_apps()
        self._state = state

    def _update_snap_apps(self) -> None:
        """Updates a snap's apps after snap changes state."""
        try:
            self._apps = self._snap_client.get_installed_snap_apps(self._name)
        except SnapAPIError:
            logger.debug(
                "Unable to retrieve snap apps for {}".format(self._name)
            )
            self._apps = []

    @property
    def present(self) -> bool:
        """Returns whether or not a snap is present."""
        return self._state in (SnapState.Present, SnapState.Latest)

    @property
    def latest(self) -> bool:
        """Returns whether the snap is the most recent version."""
        return self._state is SnapState.Latest

    @property
    def state(self) -> SnapState:
        """Returns the current snap state."""
        return self._state

    @state.setter
    def state(self, state: SnapState) -> None:
        """Sets the snap state to a given value.

        Args:
          state: a `SnapState` to reconcile the snap to.

        Raises:
          SnapError if an error is encountered
        """
        if self._state is not state:
            self.ensure(state)
        self._state = state

    @property
    def revision(self) -> str:
        """Returns the revision for a snap."""
        return self._revision

    @property
    def channel(self) -> str:
        """Returns the channel for a snap."""
        return self._channel

    @property
    def confinement(self) -> str:
        """Returns the confinement for a snap."""
        return self._confinement

    @property
    def apps(self) -> List:
        """Returns (if any) the installed apps of the snap."""
        self._update_snap_apps()
        return self._apps

    @property
    def services(self) -> Dict:
        """Returns (if any) the installed services of the snap."""
        self._update_snap_apps()
        services = {}
        for app in self._apps:
            if "daemon" in app:
                services[app["name"]] = SnapService(**app).as_dict()

        return services


class _UnixSocketConnection(http.client.HTTPConnection):
    """Implementation of HTTPConnection that connects to a named Unix socket."""

    def __init__(self, host, timeout=None, socket_path=None):
        if timeout is None:
            super().__init__(host)
        else:
            super().__init__(host, timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        """Override connect to use Unix socket (instead of TCP socket)."""
        if not hasattr(socket, "AF_UNIX"):
            raise NotImplementedError(
                "Unix sockets not supported on {}".format(sys.platform)
            )
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)


class _UnixSocketHandler(urllib.request.AbstractHTTPHandler):
    """Implementation of HTTPHandler that uses a named Unix socket."""

    def __init__(self, socket_path: str):
        super().__init__()
        self.socket_path = socket_path

    def http_open(self, req) -> http.client.HTTPResponse:
        """Override http_open to use a Unix socket connection (instead of TCP)."""
        return self.do_open(
            _UnixSocketConnection, req, socket_path=self.socket_path
        )


class SnapClient:
    """Snapd API client to talk to HTTP over UNIX sockets.

    In order to avoid shelling out and/or involving sudo in calling the snapd API,
    use a wrapper based on the Pebble Client, trimmed down to only the utility methods
    needed for talking to snapd.
    """

    def __init__(
        self,
        socket_path: str = "/run/snapd.socket",
        opener: Optional[urllib.request.OpenerDirector] = None,
        base_url: str = "http://localhost/v2/",
        timeout: float = 5.0,
    ):
        """Initialize a client instance.

        Args:
            socket_path: a path to the socket on the filesystem. Defaults to /run/snap/snapd.socket
            opener: specifies an opener for unix socket, if unspecified a default is used
            base_url: base url for making requests to the snap client. Defaults to
                http://localhost/v2/
            timeout: timeout in seconds to use when making requests to the API. Default is 5.0s.
        """
        if opener is None:
            opener = self._get_default_opener(socket_path)
        self.opener = opener
        self.base_url = base_url
        self.timeout = timeout

    @classmethod
    def _get_default_opener(cls, socket_path):
        """Build the default opener to use for requests (HTTP over Unix socket)."""
        opener = urllib.request.OpenerDirector()
        opener.add_handler(_UnixSocketHandler(socket_path))
        opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
        opener.add_handler(urllib.request.HTTPRedirectHandler())
        opener.add_handler(urllib.request.HTTPErrorProcessor())
        return opener

    def _request(
        self,
        method: str,
        path: str,
        query: Dict = None,
        body: Dict = None,
    ) -> JSONType:
        """Make a JSON request to the Snapd server with the given HTTP method and path.

        If query dict is provided, it is encoded and appended as a query string
        to the URL. If body dict is provided, it is serialied as JSON and used
        as the HTTP body (with Content-Type: "application/json"). The resulting
        body is decoded from JSON.
        """
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        response = self._request_raw(method, path, query, headers, data)
        return json.loads(response.read().decode())["result"]

    def _request_raw(
        self,
        method: str,
        path: str,
        query: Dict = None,
        headers: Dict = None,
        data: bytes = None,
    ) -> http.client.HTTPResponse:
        """Make a request to the Snapd server; return the raw HTTPResponse object."""
        url = self.base_url + path
        if query:
            url = url + "?" + urllib.parse.urlencode(query)

        if headers is None:
            headers = {}
        request = urllib.request.Request(
            url, method=method, data=data, headers=headers
        )

        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            code = e.code
            status = e.reason
            message = ""
            try:
                body = json.loads(e.read().decode())["result"]
            except (IOError, ValueError, KeyError) as e2:
                # Will only happen on read error or if Pebble sends invalid JSON.
                body = {}
                message = "{} - {}".format(type(e2).__name__, e2)
            raise SnapAPIError(body, code, status, message)
        except urllib.error.URLError as e:
            raise SnapAPIError({}, 500, "Not found", e.reason)
        return response

    def get_installed_snaps(self) -> Dict:
        """Get information about currently installed snaps."""
        return self._request("GET", "snaps")

    def get_snap_information(self, name: str) -> Dict:
        """Query the snap server for information about single snap."""
        return self._request("GET", "find", {"name": name})[0]

    def get_installed_snap_apps(self, name: str) -> List:
        """Query the snap server for apps belonging to a named, currently installed snap."""
        return self._request(
            "GET", "apps", {"names": name, "select": "service"}
        )


class SnapCache(Mapping):
    """An abstraction to represent installed/available packages.

    When instantiated, `SnapCache` iterates through the list of installed
    snaps using the `snapd` HTTP API, and a list of available snaps by reading
    the filesystem to populate the cache. Information about available snaps is lazily-loaded
    from the `snapd` API when requested.
    """

    def __init__(self):
        if not self.snapd_installed:
            raise SnapError(
                "snapd is not installed or not in /usr/bin"
            ) from None
        self._snap_client = SnapClient()
        self._snap_map = {}
        if self.snapd_installed:
            self._load_available_snaps()
            self._load_installed_snaps()

    def __contains__(self, key: str) -> bool:
        """Magic method to ease checking if a given snap is in the cache."""
        return key in self._snap_map

    def __len__(self) -> int:
        """Returns number of items in the snap cache."""
        return len(self._snap_map)

    def __iter__(self) -> Iterable["Snap"]:
        """Magic method to provide an iterator for the snap cache."""
        return iter(self._snap_map.values())

    def __getitem__(self, snap_name: str) -> Snap:
        """Return either the installed version or latest version for a given snap."""
        snap = self._snap_map.get(snap_name, None)
        if snap is None:
            # The snapd cache file may not have existed when _snap_map was
            # populated.  This is normal.
            try:
                self._snap_map[snap_name] = self._load_info(snap_name)
            except SnapAPIError:
                raise SnapNotFoundError(
                    "Snap '{}' not found!".format(snap_name)
                )

        return self._snap_map[snap_name]

    @property
    def snapd_installed(self) -> bool:
        """Check whether snapd has been installled on the system."""
        return os.path.isfile("/usr/bin/snap")

    def _load_available_snaps(self) -> None:
        """Load the list of available snaps from disk.

        Leave them empty and lazily load later if asked for.
        """
        if not os.path.isfile("/var/cache/snapd/names"):
            # The snap catalog may not be populated yet; this is normal.
            # snapd updates the cache infrequently and the cache file may not
            # currently exist.
            return

        with open("/var/cache/snapd/names", "r") as f:
            for line in f:
                if line.strip():
                    self._snap_map[line.strip()] = None

    def _load_installed_snaps(self) -> None:
        """Load the installed snaps into the dict."""
        installed = self._snap_client.get_installed_snaps()

        for i in installed:
            snap = Snap(
                name=i["name"],
                state=SnapState.Latest,
                channel=i["channel"],
                revision=i["revision"],
                confinement=i["confinement"],
                apps=i.get("apps", None),
            )
            self._snap_map[snap.name] = snap

    def _load_info(self, name) -> Snap:
        """Load info for snaps which are not installed if requested.

        Args:
            name: a string representing the name of the snap
        """
        info = self._snap_client.get_snap_information(name)

        return Snap(
            name=info["name"],
            state=SnapState.Available,
            channel=info["channel"],
            revision=info["revision"],
            confinement=info["confinement"],
            apps=None,
        )


@_cache_init
def add(
    snap_names: Union[str, List[str]],
    state: Union[str, SnapState] = SnapState.Latest,
    channel: Optional[str] = "latest",
    classic: Optional[bool] = False,
    cohort: Optional[str] = "",
) -> Union[Snap, List[Snap]]:
    """Add a snap to the system.

    Args:
        snap_names: the name or names of the snaps to install
        state: a string or `SnapState` representation of the desired state, one of
            [`Present` or `Latest`]
        channel: an (Optional) channel as a string. Defaults to 'latest'
        classic: an (Optional) boolean specifying whether it should be added with classic
            confinement. Default `False`

    Raises:
        SnapError if some snaps failed to install or were not found.
    """
    snap_names = [snap_names] if type(snap_names) is str else snap_names
    if not snap_names:
        raise TypeError("Expected at least one snap to add, received zero!")

    if type(state) is str:
        state = SnapState(state)

    return _wrap_snap_operations(snap_names, state, channel, classic, cohort)


@_cache_init
def remove(snap_names: Union[str, List[str]]) -> Union[Snap, List[Snap]]:
    """Removes a snap from the system.

    Args:
        snap_names: the name or names of the snaps to install

    Raises:
        SnapError if some snaps failed to install.
    """
    snap_names = [snap_names] if type(snap_names) is str else snap_names
    if not snap_names:
        raise TypeError("Expected at least one snap to add, received zero!")

    return _wrap_snap_operations(snap_names, SnapState.Absent, "", False)


@_cache_init
def ensure(
    snap_names: Union[str, List[str]],
    state: str,
    channel: Optional[str] = "latest",
    classic: Optional[bool] = False,
    cohort: Optional[str] = "",
) -> Union[Snap, List[Snap]]:
    """Ensures a snap is in a given state to the system.

    Args:
        name: the name(s) of the snaps to operate on
        state: a string representation of the desired state, from `SnapState`
        channel: an (Optional) channel as a string. Defaults to 'latest'
        classic: an (Optional) boolean specifying whether it should be added with classic
            confinement. Default `False`

    Raises:
        SnapError if the snap is not in the cache.
    """
    if state in ("present", "latest"):
        return add(snap_names, SnapState(state), channel, classic, cohort)
    else:
        return remove(snap_names)


def _wrap_snap_operations(
    snap_names: List[str],
    state: SnapState,
    channel: str,
    classic: bool,
    cohort: Optional[str] = "",
) -> Union[Snap, List[Snap]]:
    """Wrap common operations for bare commands."""
    snaps = {"success": [], "failed": []}

    op = "remove" if state is SnapState.Absent else "install or refresh"

    for s in snap_names:
        try:
            snap = _Cache[s]
            if state is SnapState.Absent:
                snap.ensure(state=SnapState.Absent)
            else:
                snap.ensure(
                    state=state,
                    classic=classic,
                    channel=channel,
                    cohort=cohort,
                )
            snaps["success"].append(snap)
        except SnapError as e:
            logger.warning(
                "Failed to {} snap {}: {}!".format(op, s, e.message)
            )
            snaps["failed"].append(s)
        except SnapNotFoundError:
            logger.warning("Snap '{}' not found in cache!".format(s))
            snaps["failed"].append(s)

    if len(snaps["failed"]):
        raise SnapError(
            "Failed to install or refresh snap(s): {}".format(
                ", ".join([s for s in snaps["failed"]])
            )
        )

    return (
        snaps["success"] if len(snaps["success"]) > 1 else snaps["success"][0]
    )


def install_local(
    self,
    filename: str,
    classic: Optional[bool] = False,
    dangerous: Optional[bool] = False,
) -> Snap:
    """Perform a snap operation.

    Args:
        filename: the path to a local .snap file to install
        classic: whether to use classic confinement
        dangerous: whether --dangerous should be passed to install snaps without a signature

    Raises:
        SnapError if there is a problem encountered
    """
    _cmd = [
        "snap",
        "install",
        filename,
        "--classic" if classic else "",
        "--dangerous" if dangerous else "",
    ]
    try:
        result = subprocess.check_output(
            _cmd, universal_newlines=True
        ).splitlines()[0]
        snap_name, _ = result.split(" ", 1)

        c = SnapCache()

        return c[snap_name]
    except CalledProcessError as e:
        raise SnapError(
            "Could not install snap {}: {}".format(filename, e.output)
        )


def _system_set(config_item: str, value: str) -> None:
    """Helper for setting snap system config values.

    Args:
        config_item: name of snap system setting. E.g. 'refresh.hold'
        value: value to assign
    """
    _cmd = ["snap", "set", "system", "{}={}".format(config_item, value)]
    try:
        subprocess.check_call(_cmd, universal_newlines=True)
    except CalledProcessError:
        raise SnapError(
            "Failed setting system config '{}' to '{}'".format(
                config_item, value
            )
        )


def hold_refresh(days: int = 90) -> bool:
    """Set the system-wide snap refresh hold.

    Args:
        days: number of days to hold system refreshes for. Maximum 90. Set to zero to remove hold.
    """
    # Currently the snap daemon can only hold for a maximum of 90 days
    if not isinstance(days, int) or days > 90:
        raise ValueError("days must be an int between 1 and 90")
    elif days == 0:
        _system_set("refresh.hold", "")
        logger.info("Removed system-wide snap refresh hold")
    else:
        # Add the number of days to current time
        target_date = datetime.now(timezone.utc).astimezone() + timedelta(
            days=days
        )
        # Format for the correct datetime format
        hold_date = target_date.strftime("%Y-%m-%dT%H:%M:%S%z")
        # Python dumps the offset in format '+0100', we need '+01:00'
        hold_date = "{0}:{1}".format(hold_date[:-2], hold_date[-2:])
        # Actually set the hold date
        _system_set("refresh.hold", hold_date)
        logger.info("Set system-wide snap refresh hold to: %s", hold_date)
