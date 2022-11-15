"""
Example script to show how to use HA Management
-get HA Informations
-get HA Diagnostic
-set active or set standby
-full replication
-exclude
"""

# Python Base Import
import sys
import time
import smc.examples

from smc import session
from smc.api.exceptions import HaCommandException
from smc.core.ha_management import HAManagement
from smc.elements.servers import ManagementServer


def check_diag_issue(check_for=None):
    to_return = False
    diag = HAManagement().diagnostic()
    print("diagnostic messages:")
    for infob in diag.message:
        print("title:{}".format(infob.title))
        for msg in infob.message:
            print("msg:{}".format(msg))
            if check_for is not None:
                for message in check_for:
                    if message in msg:
                        print("=>>> Issue detected =>>> {}".format(msg))
                        to_return = True

    print("diagnostic errors and warnings:")
    infob = diag.errors_warnings
    print("title:{}".format(infob.title))
    if DIAGNOSTIC_TITLE_OK not in infob.title:
        print("=>>> Issue detected =>>> {}".format(infob.title))
        to_return = True
    for msg in infob.message:
        print("msg:{}".format(msg))
        if check_for is not None:
            for message in check_for:
                if message in msg:
                    print("=>>> Issue detected =>>> {}".format(msg))
                    to_return = True

    return to_return


if __name__ == "__main__":
    DIAGNOSTIC_ERRORS = ["(Isolated)",
                         "Login status: KO"]
    DIAGNOSTIC_TITLE_OK = "No issues were detected while running the diagnostic."
    URLSMC = "https://ec2-3-70-111-86.eu-central-1.compute.amazonaws.com:8082"
    APIKEYSMC = "5s8ZwKHZFFas6NxPqQsec7Yp"
#    URLSMC = "http://localhost:8082"
#    APIKEYSMC = "HuphG4Uwg4dN6TyvorTR0001"
    try:
        session.login(url=URLSMC, api_key=APIKEYSMC, verify=False, timeout=120, api_version="7.0")
    except Exception as exception_retournee:
        sys.exit(-1)

    print("session OK")

try:
    ha = HAManagement()

    # get HA infos
    info = ha.get_ha()
    print(info)

    # display HA diagnostic
    diag_status = check_diag_issue(DIAGNOSTIC_ERRORS)
    assert not diag_status, "Issue in HA detected!"

    # check there is an active server
    assert info.active_server is not None, "No active server !"

    # try to set active the already active server.. receive an http error 400
    try:
        result = ha.set_active(info.active_server)
    except HaCommandException as ex:
        assert ex.response.status_code == 400, "Don't receive error when activating active server"

    # swap active server with first standby server
    stb_servers = info.standby_servers
    if stb_servers is not None:
        result = ha.set_active(stb_servers[0])
        print("set active {}=>{}".format(stb_servers[0], result))

    # wait for server to be active
    time.sleep(10)

    # refresh HA infos
    info = ha.get_ha()
    print(info)

    # check there is an active server
    assert info.active_server is not None, "No active server !"

    # In case of emergency set standby on active server
    active_server = info.active_server
    result = ha.set_standby(active_server)
    print("set standby {}=>{}".format(active_server, result))

    # wait for server to be stand by
    time.sleep(10)

    # refresh info
    info = ha.get_ha()
    first_standby_server = info.standby_servers[0]

    # check there is no active server
    assert info.active_server is None, "Still an active server !"

    # At this time there is no active server
    # retry activate "Management Server"
    code = 400
    mgt_server = ManagementServer("Management Server")
    retry = 0
    while code == 400 and retry < 20:
        try:
            result = ha.set_active(mgt_server)
            code = result.status_code
        except HaCommandException as ex:
            print("Exception in HA_Management, msg : {}".format(ex.smcresult.msg))
            code = ex.code
        print("try activate {}=>{}".format(mgt_server, result))
        retry += 1
        time.sleep(10)

    # wait for server to be active
    retry = 0
    while info.active_server is None and retry < 20:
        print("wait for server {} to be active".format(mgt_server, result))
        time.sleep(10)
        retry += 1
        info = ha.get_ha()

    # refresh info
    info = ha.get_ha()
    first_standby_server = info.standby_servers[0]

    # perform full replication for first standby server
    result = ha.full_replication(first_standby_server)
    print("full replication {}=>{}".format(first_standby_server, result))

    # display HA diagnostic and check if server is OK
    retry = 0
    while check_diag_issue(["(Isolated)", "Login status: KO"]) and retry < 20:
        print("full replication still in progress..")
        time.sleep(10)
        retry += 1

    # exclude from replication first standby server
    result = ha.exclude(first_standby_server)
    print("exclude {}=>{}".format(first_standby_server, result))

    # display HA diagnostic
    # At this time we should have an excluded replication issue
    diag_status = check_diag_issue(DIAGNOSTIC_ERRORS)
    assert diag_status, "Stand by server should be excluded !"

except HaCommandException as ex:
    print("Exception in HA_Management, msg : {}".format(ex.smcresult.msg))
except Exception as e:
    print(e)
finally:
    session.logout()
