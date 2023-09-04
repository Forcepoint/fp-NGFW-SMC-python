.. :changelog:

Release History
===============

1.0.0 (2017-09-03)
++++++++++++++++++

- Initial release of SMC Monitoring package
- Requires SMC 6.3.0, 6.3.1

1.1.0 (2018-02-02)
++++++++++++++++++

- Requires SMC >= 6.3.2
- ActiveAlertQuery implemented for interfacing with Alerts (requires SMC >= 6.3.3). Currently read-only
- BlacklistQuery modified to use generic log fields for all queries except fetch_as_element

1.2
+++

- VPN SA's can be deleted (requires SMC >= 6.4.2)
- Updated requirement to websocket-client 0.48.0. Fixes issue with IndexError when Tomcat 8 does not include
  the Status-Message in the initial handshake: https://github.com/websocket-client/websocket-client/issues/406

1.3.0
+++++

- Set max_recv on queries to terminate the websocket after a specified number of receives

1.3.1
+++++

- Remove kwargs from websocket call to super to support older versions of websocket-client
- Fixed fetch_batch to only return a single payload, previous versions were unlimited

1.4.0
+++++

- Update requirements to fp_NGFW_SMC_python >= 1.0.0

1.5.0
+++++

-fixed blacklist entry issue
-added first_fetch support
-added support to NumberValue and TranslatedValue in QueryFilter
-blacklist -> block_list renaming
-support "use ssl for session id" (Fix session lost issue)
-Adding asynchronious callback support (@see SMCSocketAsyncProtocol)
-support certificate options in wsocket

1.5.1
+++++

TODO



