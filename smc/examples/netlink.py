"""
Example script to show how to use Multilink Element
"""

# Python Base Import
import smc.examples

from smc import session
from smc.elements.netlink import StaticNetlink, MultilinkMember, Multilink
from smc.elements.network import Network, Router
from smc.vpn.elements import ConnectionType
from smc_info import *

if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    # create multi link
    # get first connection type
    connection_type = list(ConnectionType.objects.all())[0]
    network1 = Network("net-10.1.16.0/24")
    network2 = Network("net-172.31.16.0/24")
    router1 = Router("Etisalat Dubai Router")
    router2 = Router("Du Dubai Router")
    snl1 = StaticNetlink.create(name="SNL_Premier-ISP",
                                provider_name="ISP1",
                                output_speed=40000,
                                input_speed=40000,
                                probe_address=["10.1.16.1"],
                                network=[network1],
                                gateway=router1,
                                connection_type=connection_type,
                                )
    snl2 = StaticNetlink.create(name="SNL_Second-ISP",
                                provider_name="ISP2",
                                output_speed=50000,
                                input_speed=50000,
                                probe_address=["172.31.16.1"],
                                network=[network2],
                                gateway=router2,
                                connection_type=connection_type,
                                )

    print('SNL1\n', snl1.data.data)
    print('SNL2\n', snl2.data.data)

    print('SNL1.network\n', snl1.network)
    print('SNL2.network\n', snl2.network)
    l_ml_member = list()
    l_ml_member.append(MultilinkMember.create(netlink=snl1, netlink_role='active',
                                              ip_range='10.1.16.1-10.1.16.254'))
    l_ml_member.append(MultilinkMember.create(netlink=snl2, netlink_role='standby',
                                              ip_range='172.31.16.1-172.31.16.254'))

    oml = Multilink.create(name="OML_TEST",
                           multilink_members=l_ml_member)
    print('oml={} members={}'.format(str(oml), oml.members))
except Exception as e:
    print(e)
    exit(1)
finally:
    print("delete elements..")
    try:
        oml = Multilink.get(name="OML_TEST")
        oml.delete()
    except Exception as e:
        print(e)
    snl1 = StaticNetlink.get(name="SNL_Premier-ISP")
    snl1.delete()
    snl2 = StaticNetlink.get(name="SNL_Second-ISP")
    snl2.delete()
    session.logout()
