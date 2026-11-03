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
Get all active VPN SA's.

Create a query to obtain all connections for a given engine::

    query = VPNSAQuery('sg_vm')

Add a timezone to the query::

    query.format.timezone('CST')

Execute query and return raw results::

    for records in query.fetch_batch():
        ...

Execute query and return as a :class:`.VPNSecurityAssoc` element::

    for records in query.fetch_as_element():
        ...

Delete a VPN SA::

    query = VPNSAQuery('sg_vm')
    for sa in query.fetch_as_element():
        sa.delete()

.. seealso:: :class:`smc_monitoring.models.filters` for more information on creating filters

"""
from typing import Any, Iterator, Optional

from smc_monitoring.models.query import Query
from smc_monitoring.models.constants import LogField
from smc.base.model import prepared_request
from smc.api.exceptions import DeleteElementFailed


class VPNSAQuery(Query):
    """
    Show all current VPN SA's on the specified target.

    :ivar list field_ids: field IDs are the default fields for this entry type
        and are constants found in :class:`smc_monitoring.models.constants.LogField`

    :param str target: name of target engine/cluster
    """

    location = "/monitoring/session/socket"
    field_ids = [
        LogField.TIMESTAMP,
        LogField.NODEID,
        LogField.VPNID,
        LogField.SECURITYGATEWAY,
        LogField.PEERSECURITYGATEWAY,
        LogField.IKECOOKIE,
        LogField.ENDPOINT,
        LogField.PEERENDPOINT,
        LogField.SACLASS,
        LogField.CIPHERALG,
        LogField.NEGOTIATIONROLE,
        LogField.SRCADDRS,
        LogField.DSTADDRS,
        LogField.PROTOCOL,
        LogField.NUMBYTESSENT,
        LogField.NUMBYTESRECEIVED,
        LogField.EXPIRATIONTIME,
    ]

    def __init__(self, target: str, **kw: Any) -> None:
        super(VPNSAQuery, self).__init__("VPN_SA", target, **kw)

    def fetch_as_element(self, **kw: Any) -> Iterator["VPNSecurityAssoc"]:
        """
        Fetch the results and return as a VPNSecurityAssoc element.
        The original query is not modified.

        :param int query_timeout: length of time to wait on recieving web
            socket results (total query time).
        :param int inactivity_timeout: length of time before exiting if no new entry.
        :param int max_recv: for queries that are not 'live', set
            this to supply a max number of receive iterations.
        :return: generator of elements
        :rtype: :class:`~VPNSecurityAssoc`
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
                yield VPNSecurityAssoc(**entry)


class VPNSecurityAssoc(object):
    """
    A VPN Security Association represents a currently connected VPN
    endpoint. This is the result of making a :class:`.VPNSAQuery` and
    using :meth:`~VPNSAQuery.fetch_as_element`.
    """

    def __init__(self, **data: Any) -> None:
        self.vpn = data

    @property
    def first_fetch(self) -> Optional[bool]:
        """
        first fetch
        True means entry is part of initial data at first fetch

        :rtype: bool
        """
        return self.vpn.get("first_fetch")

    @property
    def href(self) -> Optional[str]:
        return self.vpn.get("vpn_sa_href")

    def delete(self) -> None:
        return prepared_request(DeleteElementFailed, href=self.href).delete()

    @property
    def timestamp(self) -> Optional[str]:
        """
        Timestamp of this connection. It is recommended to set the timezone
        on the query to view this timestamp in the systems local time.
        For example::

            query.format.timezone('CST')

        :rtype: str
        """
        return self.vpn.get(str(LogField.TIMESTAMP))

    @property
    def engine(self) -> Optional[str]:
        """
        The engine/cluster for this VPN

        :rtype: str
        """
        return self.vpn.get(str(LogField.NODEID))

    @property
    def local_gateway(self) -> Optional[str]:
        """
        Local gateway for this VPN.

        :rtype: str
        """
        return self.vpn.get(str(LogField.SECURITYGATEWAY))

    @property
    def peer_gateway(self) -> Optional[str]:
        """
        Peer gateway for this VPN.

        :rtype: str
        """
        return self.vpn.get(str(LogField.PEERSECURITYGATEWAY))

    @property
    def local_endpoint(self) -> Optional[str]:
        """
        Local endpoint (IP address) for this VPN tunnel.

        :rtype: str
        """
        return self.vpn.get(str(LogField.ENDPOINT))

    @property
    def peer_endpoint(self) -> Optional[str]:
        """
        Peer endpoint element and IP Address for this tunnel.

        :rtype: str
        """
        return self.vpn.get(str(LogField.PEERENDPOINT))

    @property
    def local_networks(self) -> Optional[str]:
        """
        Local protected networks

        :rtype: str
        """
        return self.vpn.get(str(LogField.SRCADDRS))

    @property
    def peer_networks(self) -> Optional[str]:
        """
        Remote protected networks

        :rtype: str
        """
        return self.vpn.get(str(LogField.DSTADDRS))

    @property
    def vpn_id(self) -> Optional[str]:
        return self.vpn.get(str(LogField.VPNID))

    @property
    def sa_type(self) -> Optional[str]:
        """
        SA Type for this VPN tunnel. Each VPN tunnel will typically have
        at least two entries, one for IPSEC and another for IKE.

        :rtype: str
        """
        return self.vpn.get(str(LogField.SACLASS))

    @property
    def protocol(self) -> Optional[str]:
        """
        WHich protocol is associated with this tunnel entry.

        :return: IP protocol for tunnel, i.e. ESP/UDP
        :rtype: str
        """
        return self.vpn.get(str(LogField.PROTOCOL))

    @property
    def negotiation_role(self) -> Optional[str]:
        """
        Role for this tunnel entry.

        :return: Negotiation role, i.e. Initiator, Responder, etc.
        :rtype: str
        """
        return self.vpn.get(str(LogField.NEGOTIATIONROLE))

    @property
    def bytes_sent(self) -> int:
        """
        Number of bytes sent.

        :rtype: int
        """
        return int(self.vpn.get(str(LogField.NUMBYTESSENT), 0))

    @property
    def bytes_received(self) -> int:
        """
        Number of bytes received.

        :rtype: int
        """
        return int(self.vpn.get(str(LogField.NUMBYTESRECEIVED), 0))

    @property
    def expiration(self) -> Optional[str]:
        """
        Expiration time for this tunnel Security Association

        :rtype: str
        """
        return self.vpn.get(str(LogField.EXPIRATIONTIME))

    def __str__(self) -> str:
        return "{}(local={},peer={},localip={},peerip={},satype={})".format(
            self.__class__.__name__,
            self.local_gateway,
            self.peer_gateway,
            self.local_endpoint,
            self.peer_endpoint,
            self.sa_type,
        )

    def __repr__(self) -> str:
        return str(self)
