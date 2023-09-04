"""
Example to show how to use an url list application
"""
import logging

from smc import session
from smc.elements.network import URLListApplication, ApplicationPort
from smc.elements.service import IPService
from smc_info import *


if __name__ == "__main__":
    logging.getLogger()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s - %(levelname)s - %(message)s",
                        datefmt="%H:%M:%S")

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    # Create Url list application with default application port
    URLListApplication().create(name="myUrlList_default",
                                url_entry=["www.foo.com", "www.bar.com"])

    url_list = URLListApplication("myUrlList_default")
    for ap in url_list.application_port:
        print("application_port={}".format(ap))
    print("url_entry={}".format(url_list.url_entry))

    # update url entry
    url_list.url_entry = ["www.new-entry.com"]
    url_list.update()

    url_list = URLListApplication("myUrlList_default")
    print("url_entry={}".format(url_list.url_entry))

    # Create Url list application
    application_port1 = ApplicationPort(port_from=443,
                                        port_to=443,
                                        protocol_ref=IPService("TCP").href,
                                        tls="free")
    url_list = URLListApplication().create(name="myUrlList",
                                           url_entry=["www.foo.com", "www.bar.com"],
                                           application_ports=[application_port1])

    url_list = URLListApplication("myUrlList")
    for ap in url_list.application_port:
        print("application_port={}".format(ap))
    print("url_entry={}".format(url_list.url_entry))

    application_port2 = ApplicationPort(port_from=8080,
                                        port_to=8080,
                                        protocol_ref=IPService("TCP").href,
                                        tls="no")
    url_list.add_application_port(application_ports=[application_port2])

    url_list = URLListApplication("myUrlList")
    for ap in url_list.application_port:
        print("application_port={}".format(ap))

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    URLListApplication("myUrlList_default").delete()
    URLListApplication("myUrlList").delete()
    session.logout()
