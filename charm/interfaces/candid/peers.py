#!/usr/bin/python
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from charms.reactive import Endpoint
from charms.reactive import when, when_not, set_flag, clear_flag


class CandidPeer(Endpoint):
    @when('endpoint.{endpoint_name}.joined')
    def changed(self):
        set_flag(self.expand_name('{endpoint_name}.connected'))
        set_flag(self.expand_name('{endpoint_name}.available'))

    @when_not('endpoint.{endpoint_name}.joined')
    def broken(self):
        clear_flag(self.expand_name('{endpoint_name}.available'))
        clear_flag(self.expand_name('{endpoint_name}.connected'))

    @property
    def addresses(self):
        """
        A flat list of all private addresses received from related units.
        This list is de-duplicated and sorted by address, so it will be stable
        for change comparison.
        """
        addrs = {u.recieved_raw['private-address']
                 for u in self.all_joined_units}
        return list(sorted(addrs))
