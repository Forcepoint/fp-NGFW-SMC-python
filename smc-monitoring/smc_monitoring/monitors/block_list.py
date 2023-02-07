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
Block_list Query provides the ability to view current block_list entries in the
SMC by target. Target is defined as the cluster or engine. Retrieved results
will have a reference to the entry and hence be possible to remove the entry.
::

    query = BlockListQuery('sg_vm')
    query.format.timezone('CST')

Optionally add an "InFilter" to restrict search to a specific field::

    query.add_in_filter(
        FieldValue(LogField.BLOCK_LISTENTRYSOURCEIP), [IPValue('2.2.2.2')])

An InFilter can also use a network based syntax::

    query.add_in_filter(
        FieldValue(LogField.BLOCK_LISTENTRYSOURCEIP), [IPValue('2.2.2.0/24')])

Or combine filters using "AndFilter" or "OrFilter". Find an entry with
source IP 2.2.2.2 OR 2.2.2.5::

    ip1 = InFilter(FieldValue(LogField.BLOCK_LISTENTRYSOURCEIP), [IPValue('2.2.2.2')])
    ip2 = InFilter(FieldValue(LogField.BLOCK_LISTENTRYSOURCEIP), [IPValue('2.2.2.5')])
    query.add_or_filter([in_filter, or_filter])

Get the results of the query in the default TableFormat::

    for entry in query.fetch_batch():
        print(entry)

Delete any block_list entries with a source IP within a network range of 3.3.3.0/24::

        query = BlockListQuery('sg_vm')
        query.add_in_filter(
            FieldValue(LogField.BLOCK_LISTENTRYSOURCEIP), [IPValue('3.3.3.0/24')])

        for record in query.fetch_as_element():  # <-- must get as element to obtain delete() method
            record.delete()

.. seealso:: :class:`smc_monitoring.models.filters` for more information on creating filters

"""
from smc_monitoring.models.query import Query
from smc_monitoring.models.formats import TextFormat, CombinedFormat, DetailedFormat
from smc_monitoring.models.constants import LogField
from smc.base.model import prepared_request
from smc.api.exceptions import DeleteElementFailed
from smc.compat import is_api_version_less_than_or_equal


class BlockListQuery(Query):
    """
    Query existing block_list entries for a given cluster/engine.
    It is generally recommended to set your local timezone when making a
    query to convert the timestamp into a relevant format.

    :param str target: NAME of the engine or cluster
    :param str timezone: timezone for timestamps.

    .. note:: Timezone can be in the following formats: 'US/Eastern',
        'PST', 'Europe/Helsinki'. More example time zone formats are
        available in the Logs view of the Management Client when you
        select Tools -> Time Zones.
    """

    location = "/monitoring/session/socket"
    field_ids = [
        LogField.TIMESTAMP,
        LogField.BLOCK_LISTER,
        LogField.BLOCK_LISTENTRYSOURCEIP,
        LogField.BLOCK_LISTENTRYDESTINATIONIP,
        LogField.PROTOCOL,
        LogField.BLOCK_LISTENTRYDURATION,
        LogField.NODEID,
        LogField.SENDERDOMAIN,
        LogField.BLOCK_LISTENTRYID,
    ]

    def __init__(self, target, timezone=None, **kw):
        super(BlockListQuery, self).__init__("BLOCK_LIST", target, **kw)

        if timezone is not None:
            self.format.set_resolving(timezone=timezone)

    def fetch_as_element(self, **kw):
        """
        Fetch the block_list and return as an instance of Element.
        :param int query_timeout: length of time to wait on recieving web
            socket results (total query time).
        :param int inactivity_timeout: length of time before exiting if no new entry.
        :param int max_recv: for queries that are not 'live', set
            this to supply a max number of receive iterations.

        :return: generator returning element instances
        :rtype: BlockListEntry
        """
        clone = self.copy()
        # Replace all filters with a combined filter
        bldata = TextFormat(field_format="name")
        # Preserve resolving fields for new filter
        if "resolving" in self.format.data:
            bldata.set_resolving(**self.format.data["resolving"])

        # Resolve the entry ID to match SMC
        blid = TextFormat(field_format="pretty")
        blid.field_ids([LogField.BLOCK_LISTENTRYID])

        combined = CombinedFormat(bldata=bldata, blid=blid)
        clone.update_format(combined)

        for list_of_results in clone.fetch_raw(**kw):
            for entry in list_of_results:
                data = entry.get("bldata")
                data.update(**entry.get("blid"))
                first_fetch = entry.get("first_fetch")
                first_fetch = first_fetch if first_fetch else False
                data.update({"first_fetch": first_fetch})
                yield BlockListEntry(**data)


class BlockListEntry(object):
    """
    A block_list entry represents an entry in the engines kernel table
    indicating that a source/destination/port/protocol mapping is currently
    being blocked by the engine. To remove a block_list entry from an engine,
    retrieve all entries as element and remove the entry of interest by
    called ``delete`` on the element.

    The simplest way to use search filters with a block_list entry is to
    examine the BlockListQuery ``field_ids`` and use these constant fields
    as InFilter definitions on the query.
    """

    def __init__(self, **kw):
        self.block_list = kw

    @property
    def block_list_id(self):
        """
        Block_list entry ID. Useful if you want to locate the entry
        within the Management Client.

        :rtype: str
        """
        return self.block_list.get("Blacklist Entry ID")

    @property
    def block_list_entry_key(self):
        """
        Block_list entry Key.
        Needed to remove the entry

        :rtype: str
        """
        return self.block_list.get("BlacklistEntryId")

    @property
    def first_fetch(self):
        """
        first fetch
        True means entry is part of initial data at first fetch

        :rtype: bool
        """
        return self.block_list.get("first_fetch")

    @property
    def timestamp(self):
        """
        Timestamp when this block_list entry was added.

        :rtype: str
        """
        return self.block_list.get("Timestamp")

    @property
    def engine(self):
        """
        The engine for this block_list entry.

        :rtype: str
        """
        return self.block_list.get("NodeId")

    @property
    def href(self):
        """
        The href for this block_list entry. This is the reference to the
        entry for deleting the entry.

        :rtype: str
        """
        return self.block_list.get("block_list_href")

    @property
    def source(self):
        """
        Source address/netmask for this block_list entry.

        :rtype: str
        """
        return "{}/{}".format(
            self.block_list.get("BlacklistEntrySourceIp"),
            self.block_list.get("BlacklistEntrySourceIpPrefixlen"),
        )

    @property
    def destination(self):
        """
        Destination network/netmask for this block_list entry.

        :rtype: str
        """
        return "{}/{}".format(
            self.block_list.get("BlacklistEntryDestinationIp"),
            self.block_list.get("BlacklistEntryDestinationIpPrefixlen"),
        )

    @property
    def protocol(self):
        """
        Specified protocol for the block_list entry. If none is specified,
        'ANY' is returned.

        :rtype: str
        """
        proto = self.block_list.get("BlacklistEntryProtocol")
        if proto is None:
            return "ANY"
        return proto

    @property
    def source_ports(self):
        """
        Source ports for this block_list entry. If no ports are specified (i.e. ALL
        ports), 'ANY' is returned.

        :rtype: str
        """
        start_port = self.block_list.get("BlacklistEntrySourcePort")
        if start_port is not None:
            return "{}-{}".format(start_port,
                                  self.block_list.get("BlacklistEntrySourcePortRange"))
        return "ANY"

    @property
    def dest_ports(self):
        """
        Destination ports for this block_list entry. If no ports are specified,
        'ANY' is returned.

        :rtype: str
        """
        start_port = self.block_list.get("BlacklistEntryDestinationPort")
        if start_port is not None:
            return "{}-{}".format(start_port,
                                  self.block_list.get("BlacklistEntryDestinationPortRange"))
        return "ANY"

    @property
    def duration(self):
        """
        Duration for the block_list entry.

        :rtype: int
        """
        return int(self.block_list.get("BlacklistEntryDuration"))

    def delete(self):
        """
        Delete the entry from the engine where the entry is applied.

        :raises: DeleteElementFailed
        :return: None
        """
        return prepared_request(DeleteElementFailed, href=self.href).delete()

    def __str__(self):
        return "{0}(id={1},src={2},dst={3})".format(
            self.__class__.__name__,
            self.block_list_id,
            self.source,
            self.destination)

    def __repr__(self):
        return str(self)
