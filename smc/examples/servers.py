"""
Example script to show how to use Servers
-get logserver
-create Netflow collector
-add Netflow collectors to log server
-remove a Netflow collector from log server
"""

# Python Base Import
import time
import requests
import smc.examples

from smc import session
from smc.administration.certificates.tls import TLSServerCredential, TLSCryptographySuite, \
    TLSProfile
from smc.elements.network import Host
from smc.elements.other import FilterExpression
from smc.elements.servers import LogServer, DataContext, NetflowCollector, ManagementServer
from smc_info import SMC_URL, API_KEY, API_VERSION


def check_if_smc_api_is_running(smc_url, cert=False):
    api_url = "{}/api".format(smc_url)
    _check_if_web_app_is_running(api_url, "version", cert, max_wait_time=180)


def _check_if_web_app_is_running(url, pattern, cert=False, max_wait_time=120):
    logger.debug("URL is ==> {}".format(url))
    api_session = requests.Session()
    timeout = time.time() + max_wait_time
    while True:
        try:
            response = api_session.get(url, verify=cert)
            if response.text.__contains__(pattern):
                logger.info("Web app is up and running")
                break
        except Exception as exc:
            # Web APP SMC API not yet ready
            logger.debug(exc)
            time.sleep(2)

        if time.time() > timeout:
            logger.error("Timeout while waiting for web app "
                         "to be up and running.")
            raise TimeoutError
        time.sleep(1)


def update_mgt_server(secure=False):
    for mgt_server in ManagementServer.objects.all():
        for webapp in mgt_server.web_app:
            print("web_app={}".format(webapp))
            if webapp["web_app_identifier"] == "smc_api":
                print("set SSL mode with SSl session ID enabled={} ..".format(secure))
                webapp["ssl_session_id"] = True if secure else False
                webapp["server_credentials_ref"] = list(TLSServerCredential.objects.all())[0].href\
                    if secure else None
                webapp["tls_cipher_suites"] = list(TLSCryptographySuite.objects.all())[0].href\
                    if secure else None
                # Save and restart mgt server
                mgt_server.update(json=mgt_server.data)


if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:

    update_mgt_server(secure=True)
    session.logout()

    # wait for webapp to restart
    SMC_URL = SMC_URL.replace("http", "https")
    check_if_smc_api_is_running(SMC_URL)

    session.login(url=SMC_URL,
                  api_key=API_KEY,
                  verify=False,
                  timeout=120,
                  api_version=API_VERSION)
    print("Login Ok")

    for log_server in LogServer.objects.all():
        print("LS={}".format(log_server))
    log_server = LogServer.get("Log Server")

    # Wait for session timeout
    print("Wait for user session timeout..")
    print("So we can force a Login refresh")
    time.sleep(120)

    # Create Netflow Collectors
    data_context = DataContext.get("All Log Data")
    filter_expression = FilterExpression.get("OMAPI Connections")
    host1 = Host.get("DNS 1")
    tls_profile = list(TLSProfile.objects.all())[0]
    tls_identity = {
        "tls_field": "IPAddress",
        "tls_value": "10.10.1.1"
    }
    netflow_collector1 = NetflowCollector(
        data_context=data_context,
        filter=filter_expression,
        host=host1,
        netflow_collector_port=255,
        netflow_collector_service="tcp_with_tls",
        netflow_collector_version="netflow_v9",
        tls_profile=tls_profile.href,
        tlsIdentity=tls_identity
    )
    host2 = Host.get("DNS 2")
    netflow_collector2 = NetflowCollector(
        data_context=data_context,
        host=host2,
        netflow_collector_port=255,
        netflow_collector_service="udp",
        netflow_collector_version="netflow_v9",
    )
    list_netflow_collector = list()
    list_netflow_collector.append(netflow_collector1)
    list_netflow_collector.append(netflow_collector2)

    # Add Netflow Collectors to log server
    print("Add netflow collector list:{}...".format(list_netflow_collector))
    log_server.add_netflow_collector(list_netflow_collector)

    for netflow_collector in log_server.netflow_collector:
        print("NF ={}".format(netflow_collector))

    print("Remove netflow collector:{}".format(netflow_collector2))
    # Remove Netflow Collector from log server
    log_server.remove_netflow_collector(netflow_collector2)

    for netflow_collector in log_server.netflow_collector:
        print("NF ={}".format(netflow_collector))

    print("Remove netflow collector:{}".format(netflow_collector1))
    # Remove Netflow Collector from log server
    log_server.remove_netflow_collector(netflow_collector1)

except Exception as e:
    print(e)
finally:
    print("Finally: Cleaning...")
    # reconnect to new session in case login refresh was not done automatically
    # SMC return 404 instead of 401 case
    session.logout()
    session.login(url=SMC_URL,
                  api_key=API_KEY,
                  verify=False,
                  timeout=120,
                  api_version=API_VERSION)
    print("Login Ok")
    print("Set server to http protocol..")
    update_mgt_server(secure=False)
    print("Wait 20s for api to restart..")
    # Have to wait some times to be sure all threads run to the web app are terminated
    time.sleep(20)
    SMC_URL = SMC_URL.replace("https", "http")
    check_if_smc_api_is_running(SMC_URL)
