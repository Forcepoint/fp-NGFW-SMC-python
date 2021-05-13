"""
Example script to show how to use Multilink Element
"""

# Python Base Import
import sys
from smc import session
from smc.elements.netlink import StaticNetlink, MultilinkMember, Multilink

if __name__ == '__main__':
    URLSMC = 'http://localhost:8082'
    APIKEYSMC = 'HuphG4Uwg4dN6TyvorTR0001'
    try:
        session.login(url=URLSMC, api_key=APIKEYSMC, verify=False, timeout=120, api_version='6.5')
    except BaseException as exception_retournee:
        sys.exit(-1)

    print("session OK")
try:
    # create multi link
    connection_type = "http://localhost:8082/6.10/elements/connection_type/1"
    snl1 = StaticNetlink.create(name="SNL_Premier-ISP",
                                provider_name="ISP1",
                                output_speed=40000,
                                input_speed=40000,
                                probe_address=["10.1.16.1"],
                                network=["http://localhost:8082/6.10/elements/network/1684"],
                                gateway="http://localhost:8082/6.10/elements/router/1682",
                                connection_type=connection_type,
                                )
    snl2 = StaticNetlink.create(name="SNL_Second-ISP",
                                provider_name="ISP2",
                                output_speed=50000,
                                input_speed=50000,
                                probe_address=["172.31.16.1"],
                                network=["http://localhost:8082/6.10/elements/network/1678"],
                                gateway="http://localhost:8082/6.10/elements/router/1676",
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
