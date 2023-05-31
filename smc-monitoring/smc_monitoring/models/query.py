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
A Query is the top level object used to construct parameters to make queries
to the SMC.

Query is the parent class for all monitors in package :py:mod:`smc_monitoring.monitors`

Each monitor type will have it's own predefined set of log fields that are considered
'default' for the query type. These will correlate closely to the default fields you will
see in the Management Client component of the SMC when viewing the same information
(Connections, VPN SAs, Blacklist, etc).

Each query also has a specific formatter which defines how the data is returned from
the query. Formatters are defined in :py:mod:`smc_monitoring.models.formats`.

Each formatter type allows customization of the field_format and allows a value of
'pretty', 'name' or 'id'. By default 'pretty' is used as the format which aligns with the
column names in the Management Client monitoring views.

"""
import copy
from smc_monitoring.wsocket import SMCSocketProtocol
from smc_monitoring.models.filters import (
    TranslatedFilter,
    InFilter,
    AndFilter,
    OrFilter,
    NotFilter,
    DefinedFilter,
)
from smc_monitoring.models.formats import TextFormat, DetailedFormat
from smc_monitoring.models.formatters import TableFormat


class Query(object):
    """
    Query is the top level structure for controlling requests over the
    SMC websocket protocol.
    Any keyword arguments are passed through from inheriting classes are
    passed through as socket options for
    :class:`smc_monitoring.wsocket.SMCSocketProtocol`.

    :ivar dict request: built request, eventually sent to socket
    :ivar TextFormat format: format settings for query
    """

    def __init__(self, definition=None, target=None, format=None, **sockopt):  # @ReservedAssignment
        """
        Create a query.

        :param str definition: used by all monitors with exception of
            LogQuery. This defines the type of session.
        :param str target: used by all monitors with exception of LogQuery.
            This identifies the engine/cluster to run the query against.
        :param format: optional format from :py:mod:`smc_monitoring.monitors`
        """
        self.request = {
            "query": {},
            "fetch": {},
            "format": {"type": "texts", "field_format": "pretty"},
        }

        self.format = format if format is not None else TextFormat()
        self.request.update(format=self.format.data)

        if target is not None:
            self.update_query(target=target)

        if definition is not None:
            self.update_query(definition=definition)

        self.sockopt = sockopt if sockopt else {}  # Optional socket options

    def copy(self):
        return copy.deepcopy(self)

    def update_query(self, **kw):
        self.request["query"].update(**kw)

    def update_format(self, format):
        """
        Update the format for this query.

        :param format: new format to use for this query
        :type format: :py:mod:`smc_monitoring.models.formats`
        """
        self.format = format
        self.request.update(format=self.format.data)

    def update_filter(self, filt):
        """
        Update the query with a new filter.

        :param QueryFilter filt: change query to use new filter
        :type filt: :class:`smc_monitoring.models.filters.QueryFilter`
        """
        self.update_query(filter=filt.filter)

    def add_translated_filter(self):
        """
        Add a translated filter to the query. A translated filter syntax
        uses the SMC expression syntax to build the filter. The simplest way to
        see the syntax is to create a filter in the Logs view of the Management
        Client and right click->Show Expression.

        Example to fetch a specific Situation from the Active Alerts::

            t_filter.update_filter('$Situation==516')
            query = ActiveAlertQuery('Shared Domain', timezone='Berlin/Europe')
            query.update_filter(t_filter)

            for record in query.fetch_batch():
                print(record)

         .. seealso:: :class:`smc_monitoring.models.filters.TranslatedFilter` for examples.

        :param values: optional constructor args for
            :class:`smc_monitoring.models.filters.TranslatedFilter`
        :type: list(QueryFilter)
        :rtype: TranslatedFilter
        """
        filt = TranslatedFilter()
        self.update_filter(filt)
        return filt

    def add_in_filter(self, *values):
        """
        Add a filter using "IN" logic. This is typically the primary filter
        that will be used to find a match and generally combines other
        filters to get more granular. An example of usage would be searching
        for an IP address (or addresses) in a specific log field. Or looking
        for an IP address in multiple log fields.

        .. seealso:: :class:`smc_monitoring.models.filters.InFilter` for examples.

        :param values: optional constructor args for
            :class:`smc_monitoring.models.filters.InFilter`
        :rtype: InFilter
        """
        filt = InFilter(*values)
        self.update_filter(filt)
        return filt

    def add_and_filter(self, *values):
        """
        Add a filter using "AND" logic. This filter is useful when requiring
        multiple matches to evaluate to true. For example, searching for
        a specific IP address in the src field and another in the dst field.

        .. seealso:: :class:`smc_monitoring.models.filters.AndFilter` for examples.

        :param values: optional constructor args for
            :class:`smc_monitoring.models.filters.AndFilter`. Typically this is
            a list of InFilter expressions.
        :type: list(QueryFilter)
        :rtype: AndFilter
        """
        filt = AndFilter(*values)
        self.update_filter(filt)
        return filt

    def add_or_filter(self, *values):
        """
        Add a filter using "OR" logic. This filter is useful when matching
        on one or more criteria. For example, searching for IP 1.1.1.1 and
        service TCP/443, or IP 1.1.1.10 and TCP/80. Either pair would produce
        a positive match.

        .. seealso:: :class:`smc_monitoring.models.filters.OrFilter` for examples.

        :param values: optional constructor args for
            :class:`smc_monitoring.models.filters.OrFilter`. Typically this is a
            list of InFilter expressions.
        :type: list(QueryFilter)
        :rtype: OrFilter
        """
        filt = OrFilter(*values)
        self.update_filter(filt)
        return filt

    def add_not_filter(self, *value):
        """
        Add a filter using "NOT" logic. Typically this filter is used in
        conjunction with and AND or OR filters, but can be used by itself
        as well. This might be more useful as a standalone filter when
        displaying logs in real time and filtering out unwanted entry types.

        .. seealso:: :class:`smc_monitoring.models.filters.NotFilter` for examples.

        :param values: optional constructor args for
            :class:`smc_monitoring.models.filters.NotFilter`. Typically this is a
            list of InFilter expressions.
        :type: list(QueryFilter)
        :rtype: OrFilter
        """
        filt = NotFilter(*value)
        self.update_filter(filt)
        return filt

    def add_defined_filter(self, *value):
        """
        Add a DefinedFilter expression to the query. This filter will be
        considered true if the :class:`smc.monitoring.values.Value` instance
        has a value.

        .. seealso:: :class:`smc_monitoring.models.filters.DefinedFilter` for examples.

        :param Value value: single value for the filter. Value is of type
            :class:`smc_monitoring.models.values.Value`.
        :type: list(QueryFilter)
        :rtype: DefinedFilter
        """
        filt = DefinedFilter(*value)
        self.update_filter(filt)
        return filt

    @staticmethod
    def resolve_field_ids(ids, **kw):
        """
        Retrieve the log field details based on the LogField constant IDs.
        This provides a helper to view the fields representation when using
        different field_formats. Each query class has a default set of field
        IDs that can easily be looked up to examine their fields and different
        label options. For example::

            Query.resolve_field_ids(ConnectionQuery.field_ids)

        :param list ids: list of log field IDs. Use LogField constants
            to simplify search.
        :return: raw dict representation of log fields
        :rtype: list(dict)
        """
        request = {
            "fetch": {"quantity": 0},
            "format": {"type": "detailed", "field_ids": ids},
            "query": {},
        }
        query = Query(**kw)
        query.location = "/monitoring/log/socket"
        query.request = request
        for fields in query.execute():
            if "fields" in fields:
                return fields["fields"]
        return []

    def _get_field_schema(self):
        """
        Get a list of all of the default fields for this query type.
        If data is available in the monitor type, a list of field definitions
        will be returned ahead of the actual data, providing insight into
        the available fields. If no data is available in a monitor, this will
        block on recv().

        :return: list of dictionary fields with the field schema
        """
        self.update_format(DetailedFormat())
        for fields in self.execute():
            if "fields" in fields:
                return fields["fields"]

    def execute(self):
        """
        Execute the query with optional timeout. The response to the execute
        query is the raw payload received from the websocket and will contain
        multiple dict keys and values. It is more common to call query.fetch_XXX
        which will filter the return result based on the method. Each result set
        will have a max batch size of 200 records. This method will also
        continuously return results until terminated. To make a single bounded
        fetch, call :meth:`.fetch_batch` or :meth:`.fetch_raw`.

        :param int sock_timeout: event loop interval
        :return: raw dict returned from query
        :rtype: dict(list)
        """
        with SMCSocketProtocol(self, **self.sockopt) as protocol:
            for result in protocol.receive():
                yield result

    def get_record(self, results):
        if "records" in results and results["records"].get("added"):
            return results["records"]["added"]

    def fetch_raw(self, **kw):
        """
        Fetch the records for this query. This fetch type will return the
        results in raw dict format. It is possible to limit the number of
        receives on the socket that return results before exiting by providing
        max_recv.

        This fetch should be used if you want to return only the result records
        returned from the query in raw dict format. Any other dict key/values
        from the raw query are ignored.

        :param int max_recv: max number of socket receive calls before
            returning from this query. If you want to wait longer for
            results before returning, increase max_iterations (default: 0)
        :param int query_timeout: length of time to wait on recieving web
            socket results (total query time).
        :param int inactivity_timeout: length of time before exiting if no new entry.
        :return: list of query results
        :rtype: list(dict)
        """
        self.sockopt.update(kw)
        with SMCSocketProtocol(self, **self.sockopt) as protocol:
            for result in protocol.receive():
                if "records" in result and result["records"].get("added"):
                    yield result["records"]["added"]

    def fetch_batch(self, formatter=TableFormat, **kw):
        """
        Fetch and return in the specified format. Output format is a formatter
        class in :py:mod:`smc_monitoring.models.formatters`. This fetch type will
        be a single shot fetch unless providing max_recv keyword with a value
        greater than the default of 1. Keyword arguments available are kw in
        :meth:`.fetch_raw`.

        :param int query_timeout: length of time to wait on recieving web
            socket results (total query time).
        :param int inactivity_timeout: length of time before exiting if no new entry.
        :param int max_recv: for queries that are not 'live', set
            this to supply a max number of receive iterations.
        :param formatter: Formatter type for data representation. Any type
            in :py:mod:`smc_monitoring.models.formatters`.
        :return: generator returning data in specified format

        .. note:: You can provide your own formatter class,
            see :py:mod:`smc_monitoring.models.formatters` for more info.
        """
        fmt = formatter(self)
        if "max_recv" not in kw:
            kw.update(max_recv=1)
        for result in self.fetch_raw(**kw):
            yield fmt.formatted(result)

    def fetch_live(self, formatter=TableFormat):
        """
        Fetch a live stream query. This is the equivalent of selecting
        the "Play" option for monitoring fields within the Management Client.
        Data will be streamed back in real time.

        :param formatter: Formatter type for data representation. Any type
            in :py:mod:`smc_monitoring.models.formatters`.
        :return: generator yielding results in specified format
        """
        fmt = formatter(self)
        for results in self.execute():
            if "records" in results and results["records"].get("added"):
                yield fmt.formatted(results["records"]["added"])

    def fetch_as_element(self):
        """
        Each inheriting class will override this method if supported.
        """
        raise NotImplementedError(
            "Implement this method on the inheriting class")
