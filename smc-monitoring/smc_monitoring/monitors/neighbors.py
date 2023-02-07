#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
"""
Neighbor Query provides the ability to view current neighbor entries from the
Neighbors viewer.
When creating the query, you must specify a target which specifies the firewall
for which to retrieve the neighbor data.

A basic neighbor query using an engine example::

    query = NeighborQuery('Plano')

You can also use standard filters to specify a more exact match, for example, showing only
neighbors using IPv6 protocol ::

    query.add_in_filter(FieldValue(LogField.NEIGHBORPROTOCOL), [StringValue("IPv6")])

"""

from smc_monitoring.models.query import Query
from smc_monitoring.models.constants import LogField


class NeighborQuery(Query):
    """
    Neighbors Query is an interface to the neighbors viewer in Log Server.
    This query type provides the ability to fetch and filter on neighbors data

    You can create a new query specifying a valid Engine name::

        query = NeighborQuery('myEngineName')

    :param str target: Engine for which to filter neighbors.
    """

    location = "/monitoring/session/socket"
    field_ids = [
        LogField.NODEID,
        LogField.RECEPTIONTIME,
        LogField.SENDERDOMAIN,
        LogField.INFOMSG,
        LogField.DATATYPE,
        LogField.DATATAGS,
        LogField.NEIGHBORSTATE,
        LogField.NEIGHBORINTERFACE,
        LogField.NEIGHBORPROTOCOL,
        LogField.NEIGHBORL3DATA,
        LogField.NEIGHBORL2DATA,
    ]

    def __init__(self, target=None):
        super(NeighborQuery, self).__init__("NEIGHBORS", target)

    def fetch_as_element(self, **kw):
        """
        Fetch the results and return as a Neighbor element. The original
        query is not modified.

        :param int query_timeout: length of time to wait on recieving web
            socket results (total query time).
        :param int inactivity_timeout: length of time before exiting if no new entry.
        :param int max_recv: for queries that are not 'live', set
            this to supply a max number of receive iterations.
        :return: generator returning element instances
        :rtype: Neighbor
        """
        clone = self.copy()
        clone.format.field_format("id")
        for custom_field in ["field_ids", "field_names"]:
            clone.format.data.pop(custom_field, None)

        for list_of_results in clone.fetch_raw(**kw):
            for entry in list_of_results:
                first_fetch = entry.get("first_fetch")
                first_fetch = first_fetch if first_fetch else False
                entry.update({"first_fetch": first_fetch})
                yield Neighbor(**entry)


class Neighbor(object):
    """
    Neighbor definition returned from specified Engine.

    This is the result of making a :class:`.NeighborQuery` and using
    :meth:`~NeighborQuery.fetch_as_element`.
    """

    def __init__(self, **data):
        self.neighbor = data

    @property
    def first_fetch(self):
        """
        first fetch
        True means entry is part of initial data at first fetch

        :rtype: bool
        """
        return self.neighbor.get("first_fetch")

    @property
    def node_id(self):
        """
        Firewall or server node that passes this information

        :rtype: str
        """
        return self.neighbor.get(str(LogField.NODEID))

    @property
    def reception_time(self):
        """
        Reception Time on the log Server

        :rtype: str
        """
        return self.neighbor.get(str(LogField.RECEPTIONTIME))

    @property
    def sender_domain(self):
        """
        Administrative Domain of Event Sender

        :rtype: str
        """
        return self.neighbor.get(str(LogField.SENDERDOMAIN))

    @property
    def data_type(self):
        """
        Data type

        :rtype: str
        """
        return self.neighbor.get(str(LogField.DATATYPE))

    @property
    def info_msg(self):
        """
        Information Message

        :rtype: str
        """
        return self.neighbor.get(str(LogField.INFOMSG))

    @property
    def data_tags(self):
        """
        Data type tag

        :rtype: str
        """
        return self.neighbor.get(str(LogField.DATATAGS))

    @property
    def neighbor_state(self):
        """
        State

        :rtype: str
        """
        return self.neighbor.get(str(LogField.NEIGHBORSTATE))

    @property
    def neighbor_interface(self):
        """
        Interface

        :rtype: str
        """
        return self.neighbor.get(str(LogField.NEIGHBORINTERFACE))

    @property
    def neighbor_protocol(self):
        """
        Protocol

        :rtype: str
        """
        return self.neighbor.get(str(LogField.NEIGHBORPROTOCOL))

    @property
    def neighbor_l3_data(self):
        """
        IP Address

        :rtype: str
        """
        return self.neighbor.get(str(LogField.NEIGHBORL3DATA))

    @property
    def neighbor_l2_data(self):
        """
        Mac address

        :rtype: str
        """
        return self.neighbor.get(str(LogField.NEIGHBORL2DATA))

    def __str__(self):
        return "{}(interface={},protocol={},state={},IP Address={},Mac Address={})".format(
            self.__class__.__name__,
            self.neighbor_interface,
            self.neighbor_protocol,
            self.neighbor_state,
            self.neighbor_l3_data,
            self.neighbor_l2_data,
        )

    def __repr__(self):
        return str(self)
