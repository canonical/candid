# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling charm state."""

import functools
import json


def requires_state_setter(func):
    @functools.wraps(func)
    def wrapper(self, event):
        if self.unit.is_leader() and self._state.is_ready():
            return func(self, event)
        else:
            return

    return wrapper


def requires_state(func):
    @functools.wraps(func)
    def wrapper(self, event):
        if self._state.is_ready():
            return func(self, event)
        else:
            event.defer()
            return

    return wrapper


class State:
    """A magic state that uses a relation as the data store.

    The get_relation callable is used to retrieve the relation.
    As relation data values must be strings, all values are JSON encoded.
    """

    def __init__(self, app, get_relation):
        """Construct.

        Args:
            app: workload application
            get_relation: get peer relation method
        """
        # Use __dict__ to avoid calling __setattr__ and subsequent infinite recursion.
        self.__dict__["_app"] = app
        self.__dict__["_get_relation"] = get_relation

    def __setattr__(self, name, value):
        """Set a value in the store with the given name.

        Args:
            name: name of value to set in store.
            value: value to set in store.
        """
        v = json.dumps(value)
        self._get_relation().data[self._app].update({name: v})

    def __getattr__(self, name):
        """Get from the store the value with the given name, or None.

        Args:
            name: name of value to get from store.

        Returns:
            value from store with given name.
        """
        v = self._get_relation().data[self._app].get(name, "null")
        return json.loads(v)

    def __delattr__(self, name):
        """Delete the value with the given name from the store, if it exists.

        Args:
            name: name of value to delete from store.

        Returns:
            deleted value from store.
        """
        return self._get_relation().data[self._app].pop(name, None)

    def is_ready(self):
        """Report whether the relation is ready to be used.

        Returns:
            A boolean representing whether the relation is ready to be used or not.
        """
        return bool(self._get_relation())
