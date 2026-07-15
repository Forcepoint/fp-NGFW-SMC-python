from __future__ import annotations
from typing import Any, Optional, Union, Iterator
from smc.base.structs import NestedDict


class AutomaticRulesSettings(NestedDict):
    """
    Represents the container for all automatic rules settings for a cluster.
    """

    def __init__(self, engine: Any) -> None:
        ars = engine.data.get("automatic_rules_settings", {})
        super(AutomaticRulesSettings, self).__init__(data=ars)

    def update_automatic_rules_settings(self, **kw: Any) -> None:
        """
        Update the required automatic_rules_settings settings.
        :param kw: Multiple automatic rule settings are going to be updated at the same time.
        """
        temp_dict = dict()
        for setting, value in kw.items():
            if setting in ['allow_auth_traffic', 'allow_connections_to_dns_resolvers',
                           'allow_connections_to_remote_dhcp_server',
                           'allow_icmp_traffic_for_route_probing',
                           'allow_listening_interfaces_to_dns_relay_port', 'allow_no_nat',
                           'log_level']:
                temp_dict[setting] = value
        self.update(temp_dict)

    @property
    def allow_auth_traffic(self) -> Optional[bool]:
        """
        Return Allow Auth Traffic Setting.
        :rtype Boolean:
        """
        return self.data.allow_auth_traffic

    @property
    def allow_connections_to_dns_resolvers(self) -> Optional[bool]:
        """
        Return Allow connections to dns resolvers
        :rtype Boolean:
        """
        return self.data.allow_connections_to_dns_resolvers

    @property
    def allow_connections_to_remote_dhcp_server(self) -> Optional[bool]:
        """
        Return Allow connections to remote dhcp server
        :rtype Boolean:
        """
        return self.data.allow_connections_to_remote_dhcp_server

    def allow_icmp_traffic_for_route_probing(self) -> Optional[bool]:
        """
        Return Allow icmp traffic for route probing setting
        :rtype Boolean:
        """
        return self.data.allow_icmp_traffic_for_route_probing

    @property
    def allow_listening_interfaces_to_dns_relay_port(self) -> Optional[bool]:
        """
        Return Allow listening interfaces to dns relay port setting
        :rtype Boolean:
        """
        return self.data.allow_listening_interfaces_to_dns_relay_port

    @property
    def allow_no_nat(self) -> Optional[bool]:
        """
        Return Allow no nat setting
        :rtype Boolean:
        """
        return self.data.allow_no_nat

    @property
    def log_level(self) -> Optional[str]:
        """
        Return Log Level
        :rtype str: Log level
        """
        return self.data.log_level
