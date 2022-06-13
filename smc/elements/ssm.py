"""
Module providing sidewinder element creation.

The different sidewinder elements in this module that can be configured are SSM
Logging Profiles, SSH Profiles, SSH Known Hosts, and SSH Known Hosts Lists.

"""
from smc.base.model import Element, ElementCreator


class SSMLoggingProfile(Element):

    typeof = "sidewinder_logging_profile"


class SSHProfile(Element):
    """
    Class representing a SSH Profile object used in SSM SSH Proxy services

    Create a SSH Profile element with ciphers, kex, and macs::

        SSHProfile.create(name='mysshprofile',
                    cipher='aes256-ctr,aes128-ctr,aes192-ctr,aes128-cbc',
                    kex='ecdh-sha2-nistp256,diffie-hellman-group14-sha1',
                    mac='hmac-sha2-256,hmac-sha2-512,hmac-md5-etm@openssh.com',
                    comment='some comment for my ssh profile')

    Available attributes:

    :ivar str cipher: cipher algorithms set for this element
    :ivar str kex: key exchange algorithms set for this element
    :ivar str mac: mac algorithms set for this element

    .. note:: Each algorithm type must have an algorithm set
    """

    typeof = "ssh_profile"

    @classmethod
    def create(
        cls,
        name,
        cipher,
        kex,
        mac,
        comment=None
    ):
        """
        Create the SSH Profile

        :param str name: name of ssh profile
        :param str cipher: string of cipher algorithms (comma separated)
        :param str kex: string of key exchange algorithms (comma separated)
        :param str mac: string of mac algorithms (comma separated)
        :param str comment: comment (optional)
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: SSHProfile

        .. note:: No algorithm type can be empty
        """

        json = {
            "name": name,
            "ciphers": cipher,
            "key_exchanges": kex,
            "macs": mac,
            "comment": comment
        }

        return ElementCreator(cls, json)


class SSHKnownHosts(Element):
    """
    Class representing a SSH Known Host object used in SSH Known Hosts Lists

    Create a SSH Knwown Host element with ipv4 and with ssh-rsa::

        SSHKnownHosts.create(name='ipv4_rsa_known_host',
                    sshkey_type='ssh-rsa',
                    host_key='<ssh_host_rsa_key.pub output>',
                    ipaddress='1.1.1.1', port=22000,
                    comment='some comment for my known host')

    Create a SSH Knwown Host element with ipv6 and with ecdsa-sha2-nistp256::

        Host.create(name='ipv6_ecdsa_known_host',
                    ssh_type='ecdsa-sha2-nistp256',
                    host_key='<ssh_host_ecdsa_key.pub output>',
                    ipv6_address='2001:cdba::3257:9652')

    Available attributes:

    :ivar str ipaddress: IPv4 address for this element
    :ivar str ipv6_address: IPv6 address for this element
    :ivar str sshkey_type: ssh key type (i.e. ssh-rsa, ecdsa-sha2-nistp256)
    :ivar str host_key: public host key of host
    :ivar int port: port number for this element
    """

    typeof = "known_host"

    @classmethod
    def create(
        cls,
        name,
        host_key,
        sshkey_type,
        ipaddress=None,
        ipv6_address=None,
        port=22,
        comment=None
    ):

        """
        Create the SSH Known Host

        :param str name: name of ssh known host
        :param str host_key: string of public host key of known host
        :param str sshkey_type: ssh key type of the known host public key
        :param str ipaddress: IPv4 address of known host
        :param str ipv6_ipaddress: IPv6 address of known host
        :param int port: port number of the ssh known host element
        :param str comment: comment (optional)
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: SSHKnownHosts

        .. note:: Either an ipaddress or ipv6_address must be specified
        """

        ipaddress = ipaddress if ipaddress else None
        ipv6_address = ipv6_address if ipv6_address else None

        json = {
            "name": name,
            "ipaddress": ipaddress,
            "ipv6_address": ipv6_address,
            "known_host_public_key": host_key,
            "sshkey_type": sshkey_type,
            "port": port,
            "comment": comment
        }

        return ElementCreator(cls, json)


class SSHKnownHostsLists(Element):
    """
    Class representing a SSH Known Hosts List object used in the Sidewinder
    Proxy Add-On on the engine

    Create a SSH Knwown Hosts List element and add a created Known Host to it::

        known_host = SSHKnownHosts.create(name='ipv4_rsa_known_host',
                                sshkey_type='ssh-rsa',
                                host_key='<ssh_host_rsa_key.pub output>',
                                ipaddress='1.1.1.1', port=22000,
                                comment='some comment for my known host')

        SSHKnownHostsLists.create(name='myknownhostslist',
                    known_host=[known_host.href],
                    comment='some comment for my known host list')

    Available attributes:

    :ivar list known_host: href of known host for this element
    """

    typeof = "known_host_list"

    @classmethod
    def create(
        cls,
        name,
        known_host=[],
        comment=None
    ):

        """
        Create the SSH Known Host List

        :param str name: name of ssh known host list
        :param list known_host: href of ssh known hosts to add to the list
        :param str comment: comment (optional)
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: SSHKnownHostsLists
        """

        json = {
            "name": name,
            "element": known_host,
            "comment": comment
        }

        return ElementCreator(cls, json)
