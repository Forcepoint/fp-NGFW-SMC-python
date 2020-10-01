#!/usr/bin/python


################################################
#    Customize these variable                  #
################################################

smc_url = 'http://localhost:8082'
smc_key = 'HuphG4Uwg4dN6TyvorTR0001'

smc_domain = ''
api_version='6.9'
timeout = 180

################################################
#Login the api
from smc import session
from smc.core.engines import CloudSGSingleFW

session.login(url=smc_url, domain=smc_domain, api_key=smc_key,
              api_version=api_version, timeout=timeout, verify=False)

from smc.core.engine import Engine


try:
    # Cloud engine creation
    print("Create cloud fw: Cloud Single firewall 1...")
    CloudSGSingleFW.create_dynamic(interface_id=0, name='Cloud Single firewall 1')

    # Should not use regular create method but create_dynamic instead
    # Since cloud firewall should use dynamic interface
    try:
        CloudSGSingleFW.create(name='test cloud name', mgmt_ip='1.1.1.1', mgmt_network='1.1.1.0/24')
    except Exception as e:
        print("regular create method not supported : %s" % str(e))
        print("The example can continue..")

    # Retrieve the Engine
    print("Get cloud fw...")
    engine = Engine('Cloud Single firewall 1')
    print(list(engine.nodes))

    print("======================================================================================")
    print("Firewall name: %s" % engine)
    print("Firewall REF: %s" % engine.href)
    for node in engine.nodes:
        print("Firewall nodes: %s" % node)
        print("Firewall nodes: %s" % node.href)
    print("======================================================================================")

    # Check node status
    print("Get node status...")
    for node in engine.nodes:
        print("Firewall node %s status: %s" % (node.name, str(node.status())))

    # Delete Engine
    engine.delete()

except Exception as e:
    print ("Example failed:"+str(e));
    engine = Engine('Cloud Single firewall 1')
    engine.delete()
    session.logout()
    exit(1)

session.logout()
