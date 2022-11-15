"""
Example script to show how to subscribe to LOGS notifications using websocket library
or smc_monitoring extension and to use filters
"""


# Python Base Import
import json
import ssl
import smc.examples


from websocket import create_connection

from smc import session
from smc_monitoring.monitors.logs import LogQuery
from smc_monitoring.models.values import FieldValue, NumberValue, TranslatedValue, ServiceValue
from smc_monitoring.models.filters import InFilter, QueryFilter
from smc_monitoring.models.constants import LogField

from smc_info import SMC_URL, API_KEY, API_VERSION, WS_URL

FILTER_FAILED = "filter failed!"

if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    print("Retrieve logs using websocket library")

    ws = create_connection(
        "{}/{}/monitoring/log/socket".format(WS_URL, str(API_VERSION)),
        cookie=session.session_id,
        socket=session.sock,
        sslopt={"cert_reqs": ssl.CERT_NONE}
    )

    # show how to use operator "or" with  source port = 22, 25
    #                                 or type translated source port = 7000
    #                                 or type translated dst ip = 74.125.127.191
    #                                 or type translated protocol = "TCP"
    query = {
        'query': {'start_ms': 0, 'end_ms': 0, 'type': 'stored',
                  "filter": {"type": "or",
                             "values": [
                                 {"type": "in", "left": {"type": "field", "id": LogField.DPORT},
                                  "right": [{"type": "number", "value": 22},
                                            {"type": "number", "value": 25}]},
                                 {"type": "translated", "value": "$Sport == 7000"},
                                 {"type": "translated", "value": "$Dst == ipv4( 74.125.127.191 )"},
                                 {"type": "translated", "value": "$Protocol == \"TCP\""}]
                             }},
        'fetch': {'quantity': 1, 'backwards': True},
        'format': {'type': 'texts', 'field_format': 'pretty', 'resolving': {'senders': True}}
    }

    try:
        print("Get filtered logs using native Websocket..")
        ws.send(json.dumps(query))
        result = ws.recv()
        print("Received '{}'".format(result))
        fetch_id = json.loads(result)['fetch']
        result = ws.recv()
        print("Received '{}'".format(result))

    finally:
        ses_mon_abort_query = {"abort": fetch_id}
        ws.send(json.dumps(ses_mon_abort_query))
        ws.close()

    # test NumberValue
    print("")
    print("Get filtered dst port or service logs using LogQuery add_or_filter and InFilter..")
    query = LogQuery(fetch_size=10)
    query.add_or_filter([
        InFilter(FieldValue(LogField.DPORT), [NumberValue(80)]),
        InFilter(FieldValue(LogField.SERVICE), [ServiceValue('TCP/80')])])

    a = list(query.fetch_raw())
    for log in a:
        for entry in log:
            print(entry)
            dst_port = entry.get("Dst Port")
            assert (dst_port == '80'), FILTER_FAILED

    # test NumberValue
    print("")
    print("Get filtered dst port logs using LogQuery add_in_filter..")
    query = LogQuery(fetch_size=10)
    query.add_in_filter(FieldValue(LogField.DPORT), [NumberValue(22, 25)])

    a = list(query.fetch_raw())
    for log in a:
        for entry in log:
            print(entry)
            dst_port = entry.get("Dst Port")
            assert (dst_port == '22' or dst_port == '25'), FILTER_FAILED

    # test TranslatedFilter
    print("")
    print("Get filtered src port logs using LogQuery translated_filter..")
    query = LogQuery(fetch_size=10)
    translated_filter = query.add_translated_filter()
    translated_filter.update_filter("$Sport == 7000 OR $Sport == 7001")

    a = list(query.fetch_raw())
    for log in a:
        for entry in log:
            print(entry)
            src_port = entry.get("Src Port")
            assert (src_port == '7000' or src_port == '7001'), FILTER_FAILED

    #   test TranslatedFilter with defined functions example
    print("")
    print("Get filtered logs using LogQuery translated_filter special functions..")
    query = LogQuery(fetch_size=10)
    translated_filter = query.add_translated_filter()
    # use special filter functions
    translated_filter.within_ipv4_network('$Dst', ['192.168.4.0/24'])
#    translated_filter.within_ipv4_range('$Src', ['1.1.1.1-192.168.1.254'])
#    translated_filter.exact_ipv4_match('$Src', ['172.18.1.152', '192.168.4.84'])

    a = list(query.fetch_raw())
    for log in a:
        print(log)

    # test TranslatedValue
    print("")
    print("Get filtered dst port logs using LogQuery QueryFilter update_filter TranslatedValue..")
    query = LogQuery(fetch_size=10)
    query_filter = QueryFilter("translated")
    query_filter.update_filter(TranslatedValue("$Dport == 22 OR $Dport == 25").value)
    query.update_filter(query_filter)

    a = list(query.fetch_raw())
    for log in a:
        for entry in log:
            print(entry)
            dst_port = entry.get("Dst Port")
            assert (dst_port == '22' or dst_port == '25'), FILTER_FAILED

except BaseException as e:
    print(e)
    exit(-1)
finally:
    session.logout()
