#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
"""
Constants used within :py:mod:`smc_monitoring.models.values.Value` values to simplify
referencing log viewer data.
"""


class LogField:
    """
    Log field constants can be referenced when creating filters such
    as Field Values. i.e. FieldValue(LogField.SRC). Each constant name is identical
    to the value when using the field format type of 'name' (with exception that
    the constant names are in upper case).
    """

    TIMESTAMP = 1  #: Time of creating the event record.
    LOGID = 2  #: Data Identifier
    COMPID = 3  #: The identifier of the creator of the log entry.
    NODEID = 4  #: Firewall or server node that passes this information
    SENDER = 5  #: None
    EVENT = 6  #: Logged event
    SRC = 7  #: Connection source IP address
    DST = 8  #: Connection destination IP address
    SPORT = 9  #: Connection source protocol port
    DPORT = 10  #: Connection destination protocol port
    PROTOCOL = 11  #: IP protocol
    SRCIF = 12  #: Source interface of firewall
    DSTIF = 13  #: Destination interface of firewall
    ACTION = 14  #: Connection action
    NATSRC = 15  #: Translated packet source IP address
    NATDST = 16  #: Translated packet destination IP address
    NATSPORT = 17  #: Translated packet source protocol port
    NATDPORT = 18  #: Translated packet destination port
    INFOMSG = 19  #: Information Message
    RULEID = 20  #: Rule tag value of acceptance rule
    NATRULEID = 21  #: The rule number of the rule that led to the log creation
    FACILITY = 22  #: Firewall subsystem
    TYPE = 23  #: Log event severity type
    RECEPTIONTIME = 24  #: Reception Time on the log Server
    ALERT = 25  #: Type of alert
    TRANSIENT = 26  #: None
    #: Special field for filtering logs using the defined services.
    # Not present in the log entries as such.
    SERVICE = 27
    CONTROLCOMMANDID = 28  #: None
    ACK = 29  #: Acknowledged Alert
    STORAGESERVERID = 30  #: Storage Server
    SENDERTYPE = 31  #: Sender type
    DATATYPE = 34  #: Data type
    INTERFACE = 35  #: Interface
    #: The type of the situation that caused sending this event.
    SITCATEGORY = 37
    SENDERDOMAIN = 38  #: Administrative Domain of Event Sender
    TLSCERTIFICATEVERIFYERRORCODE = 39  #: TLS/SSL Certificate verify error code
    TLSDOMAIN = 40  #: Domain name field in SSL/TLS certificate
    TLSPROTOCOLVERSION = 41  #: TLS/SSL protocol version
    TLSCIPHERSUITE = 42  #: TLS/SSL cipher suite
    TLSCOMPRESSIONMETHOD = 43  #: TLS/SSL compression method
    TLSALERTLEVEL = 44  #: TLS/SSL Alert Message Alert Level
    TLSALERTDESCRIPTION = 45  #: TLS/SSL Alert Message Description
    SRCZONE = 46  #: Connection source interface zone
    DSTZONE = 47  #: Connection destination interface zone
    HITS = 48  #: HITS
    RETSRCIF = 49  #: Return source interface of the connection
    SNMPSRCIF = 50  #: SNMP index of source interface
    SNMPRETSRCIF = 51  #: SNMP index of return source interface
    #: The type of the application that caused sending this event.
    APPLICATIONUSAGE = 52
    #: The type of the URL that caused sending this event.
    URLCATEGORYGROUP = 53
    #: Anomaly information of certain combination of network application and client application.
    APPLICATIONCOMBINATIONFLAGS = 54
    #: The risk of the URL that caused sending this event.
    URLCATEGORYRISK = 55
    #: The type of the file that caused sending this event.
    FILETYPECOMPAT = 56
    FPCACHED = 57  #: Fingerprint match came from fingerprinting cache.
    APPLICATION = 800  #: Application
    APPLICATIONDETAIL = 801  #: Application Detail
    SESSIONID = 802  #: Id of the User Session
    MESSAGEID = 804  #: Message Id
    LOGSEVERITY = 805  #: Severity
    RESOURCE = 806  #: Resource
    SSLVPNSESSIONTYPETYPE = 808  #: SSL VPN session client type
    #: Node's local time when the SSL VPN session was created
    SSLVPNSESSIONMONRECEIVED = 809
    #: Node's local time when the SSL VPN session will time-out
    SSLVPNSESSIONMONTIMEOUT = 810
    SSLVPNSESSIONMONID = 811  #: Id of the User Session
    #: Number of tunneling protocol layers encapsulating this protocol layer
    TUNNELINGLEVEL = 95
    ICMPTYPE = 100  #: ICMP type attribute
    ICMPCODE = 101  #: ICMP code attribute
    ICMPID = 102  #: ICMP identifier
    IPSECSSPI = 103  #: Inbound IPsec SPI value (hexadecimal)
    ACCELAPSED = 104  #: Elapsed time of connection in seconds
    ACCTXBYTES = 105  #: Number of bytes sent during connection
    ACCRXBYTES = 106  #: Number of bytes received during connection
    AUTHRULEID = 107  #: The rule number of the rule that led to the log creation
    AUTHNAME = 108  #: User name of authorized user
    RTT = 109  #: Round trip time of connection establishing
    SRVHELPERID = 110  #: Protocol agent identification
    SYSLOGTYPE = 111  #: Syslog message type
    SRCVLAN = 112  #: Source VLAN
    DSTVLAN = 113  #: Destination VLAN
    FLAG = 114  #: None
    TIMEOUT = 115  #: Connection timeout in connection monitoring
    STATE = 116  #: Connection state in connection monitoring
    BLACKLISTENTRYID = 117  #: None
    BLACKLISTENTRYSOURCEIP = 118  #: Blacklist entry source IP address
    BLACKLISTENTRYSOURCEIPMASK = 119  #: Blacklist entry source IP address mask
    BLACKLISTENTRYDESTINATIONIP = 120  #: Blacklist entry destination IP address
    #: Blacklist entry destination IP address mask
    BLACKLISTENTRYDESTINATIONIPMASK = 121
    BLACKLISTENTRYPROTOCOL = 122  #: Blacklist entry IP protocol
    BLACKLISTENTRYSOURCEPORT = 123  #: Blacklist entry source port
    BLACKLISTENTRYSOURCEPORTRANGE = 124  #: Blacklist entry source port range end
    BLACKLISTENTRYDESTINATIONPORT = 125  #: Blacklist entry destination port
    #: Blacklist entry destination port range end
    BLACKLISTENTRYDESTINATIONPORTRANGE = 126
    BLACKLISTENTRYDURATION = 127  #: Blacklist entry duration
    BLACKLISTER = 128  #: Blacklister
    # BLOCK_LIST renaming
    BLOCK_LISTENTRYID = 117  #: None
    BLOCK_LISTENTRYSOURCEIP = 118  #: block_list entry source IP address
    BLOCK_LISTENTRYSOURCEIPMASK = 119  #: block_list entry source IP address mask
    BLOCK_LISTENTRYDESTINATIONIP = 120  #: block_list entry destination IP address
    #: block_list entry destination IP address mask
    BLOCK_LISTENTRYDESTINATIONIPMASK = 121
    BLOCK_LISTENTRYPROTOCOL = 122  #: block_list entry IP protocol
    BLOCK_LISTENTRYSOURCEPORT = 123  #: block_list entry source port
    BLOCK_LISTENTRYSOURCEPORTRANGE = 124  #: block_list entry source port range end
    BLOCK_LISTENTRYDESTINATIONPORT = 125  #: block_list entry destination port
    #: block_list entry destination port range end
    BLOCK_LISTENTRYDESTINATIONPORTRANGE = 126
    BLOCK_LISTENTRYDURATION = 127  #: block_list entry duration
    BLOCK_LISTER = 128  #: block_lister

    QOSCLASS = 129  #: QoS Class
    DSCPMARK = 130  #: DSCP Mark
    QOSPRIORITY = 131  #: QoS Priority
    SERVICEKEY = 132  #: Service primary key, used in service resolving
    AUTHMETHOD = 133  #: Authentication Method element
    IPSAPPID = 134  #: Network application detected in the connection
    #: TLS Match detected in the connection. Note that a single connection
    # can have any number of distinct TLS Matches.
    TLSMATCH = 135
    TLSDETECTED = 136  #: The connection uses SSL/TLS protocol.
    #: The connection was decrypted and re-encrypted in the engine to perform d
    # eep inspection or application identification.
    TLSDECRYPTED = 137
    ACCTXPACKETS = 138  #: Number of packets sent during connection
    ACCRXPACKETS = 139  #: Number of packets received during connection
    ASPAMSENDEREMAIL = 150  #: Sender email address
    ASPAMRECEIVEREMAIL = 151  #: Receiver email address
    ASPAMEMAILSUBJECT = 152  #: Email subject
    ASPAMEMAILSCORE = 153  #: Email score value
    ASPAMSENDERMTA = 154  #: Sender Message Transfer Agent IP address
    ASPAMEMAILMESSAGEID = 155  #: Email message-ID
    ROUTENETWORK = 160  #: Network address of the network
    ROUTENETMASK = 161  #: Netmask address of the network
    ROUTEDISTANCE = 162  #: Relative distance for route validation
    ROUTEMETRIC = 163  #: Protocol specific metric value
    ROUTEGATEWAY = 164  #: IP address of the gateway for the route
    ROUTETYPE = 165  #: Type of route
    ROUTEOSPFLSATYPE = 166  #: Type of OSPF LSA's
    ROUTEBGPPATH = 167  #: Active BGP path
    POTENTIALLYDUPLICATERESPONSE = 170  #: Potentially duplicate correlation response
    #: Blacklist entry source IP address prefix length
    BLACKLISTENTRYSOURCEIPPREFIXLEN = 172
    BLACKLISTENTRYDESTINATIONIPPREFIXLEN = (
        173  #: Blacklist entry destination IP address prefix length
    )
    # BLOCK_LIST renaming
    #: block_list entry source IP address prefix length
    BLOCK_LISTENTRYSOURCEIPPREFIXLEN = 172
    BLOCK_LISTENTRYDESTINATIONIPPREFIXLEN = (
        173  #: block_list entry destination IP address prefix length
    )
    SFPINGRESS = 900  #: SFP_INGRESS
    IKEDHGROUP = 901  #: Diffie-Hellman Group
    RWPHTTPREFERRER = 832  #: HTTP Referrer
    NODESTATUS = 300  #: Node status
    NODEVERSION = 301  #: Node version
    #: Session monitoring event code (1 = new, 2 = update, 3 = remove, 4 = all sessions sent)
    SESSIONEVENT = 302
    NODEDYNUP = 303  #: Update package level
    NODECONFIGURATION = 304  #: Current configuration
    NODECONFIGURATIONTIMESTAMP = 305  #: Configuration upload time
    CONNECTIVITY = 306  #: Connectivity
    PEERCOMPONENTID = 307  #: Peer component id
    CONNTYPE = 308  #: Connection type
    CONNSTATUS = 309  #: Connection status
    CONNDIRECTION = 310  #: Connection direction
    STATUSTYPE = 311  #: Status type
    NODEHWSTATUS = 315  #: Node hardware status
    TCPDUMPSTATUS = 318  #: TCPDump Monitoring Status
    TRAFFICCOUNTERS = 319  #: Traffic counters
    NODELOAD = 320  #: Node load
    NODECAPACITY = 321  #: Capacity
    FWRECEIVEDBYTES = 322  #: FW_RECEIVED_BYTES
    FWRECEIVEDPACKETS = 323  #: FW_RECEIVED_PACKETS
    FWSENTBYTES = 324  #: FW_SENT_BYTES
    FWSENTPACKETS = 325  #: FW_SENT_PACKETS
    FWACCEPTEDBYTES = 326  #: FW_ACCEPTED_BYTES
    FWACCEPTEDPACKETS = 327  #: FW_ACCEPTED_PACKETS
    FWDROPPEDBYTES = 328  #: FW_DROPPED_BYTES
    FWDROPPEDPACKETS = 329  #: FW_DROPPED_PACKETS
    FWENCRYPTEDBYTES = 330  #: FW_ENCRYPTED_BYTES
    FWENCRYPTEDPACKETS = 331  #: FW_ENCRYPTED_PACKETS
    FWDECRYPTEDBYTES = 332  #: FW_DECRYPTED_BYTES
    FWDECRYPTEDPACKETS = 333  #: FW_DECRYPTED_PACKETS
    FWNATTEDBYTES = 334  #: FW_NATTED_BYTES
    FWNATTEDPACKETS = 335  #: FW_NATTED_PACKETS
    FWACCOUNTEDBYTES = 336  #: FW_ACCOUNTED_BYTES
    FWACCOUNTEDPACKETS = 337  #: FW_ACCOUNTED_PACKETS
    SENSORRECEIVEDBYTES = 338  #: Bytes received by sensor
    SENSORRECEIVEDPACKETS = 339  #: Packets received by sensor
    FWINTERFACEKEY = 340  #: FW_INTERFACE_KEY
    FWTRAFFIC = 342  #: FW Traffic
    FWTRAFFICALLOWEDPACKETS = 343  #: Allowed Packets
    FWTRAFFICDISCARDEDPACKETS = 344  #: Discarded Packets
    FWTRAFFICLOGGEDPACKETS = 345  #: Logged Packets
    FWTRAFFICACCOUNTEDPACKETS = 346  #: Accounted Packets
    FWTRAFFICNATTEDPACKETS = 347  #: Natted Packets
    FWTRAFFICENCRYPTEDPACKETS = 348  #: Encrypted Packets
    FWTRAFFICALLOWEDBYTES = 349  #: Allowed Bytes
    FWTRAFFICDISCARDEDBYTES = 350  #: Discarded Bytes
    FWTRAFFICLOGGEDBYTES = 351  #: Logged Bytes
    FWTRAFFICACCOUNTEDBYTES = 352  #: Accounted Bytes
    FWTRAFFICNATTEDBYTES = 353  #: Natted Bytes
    FWTRAFFICENCRYPTEDBYTES = 354  #: Encrypted Bytes
    SENSORPROCESSEDBYTES = 355  #: Bytes processed by sensor
    SENSORPROCESSEDPACKETS = 356  #: Packets processed by sensor
    SENSORINSPECTEDBYTES = 357  #: Bytes inspected by sensor
    SENSORINSPECTEDPACKETS = 358  #: Packets inspected by sensor
    SENSORLOSTBYTES = 359  #: Bytes lost in sensor
    SENSORLOSTPACKETS = 360  #: Packets lost in sensor
    RECEIVEDLOGEVENTS = 361  #: RECEIVED_LOG_EVENTS
    SENTLOGEVENTS = 362  #: SENT_LOG_EVENTS
    NUMLOGEVENTS = 363  #: Number of log events
    NUMLOGRESPONSES = 364  #: Number of log responses performed by this engine
    NUMALERTRESPONSES = 365  #: Number of alert responses performed by this engine
    NUMRECORDRESPONSES = 366  #: Number of record responses performed by this engine
    NUMRESETRESPONSES = 367  #: Number of reset responses performed by this engine
    NUMDISCARDRESPONSES = 368  #: Number of discard responses performed by this engine
    NUMBLACKLISTRESPONSES = 369  #: Number of blacklist responses performed by this engine
    # BLACKLIST renaming
    NUMBLOCK_LISTRESPONSES = 369  #: Number of block_list responses performed by this engine
    SENSORINTERFACEKEY = 370  #: Sensor interface key
    SENSORTRAFFIC = 372  #: Sensor traffic
    SENSORTRAFFICPROCESSEDPACKETS = 373  #: Processed Packets
    SENSORTRAFFICPROCESSEDBYTES = 374  #: Processed Bytes
    SENSORTRAFFICLOSTPACKETS = 375  #: Lost Packets
    SENSORTRAFFICINSPECTEDPACKETS = 376  #: Inspected Packets
    SENSORTRAFFICSTATSOFPACKETS = 377  #: Stats Of Packets
    SENSORTRAFFICOKCONNECTIONS = 378  #: OK Connections
    SENSORTRAFFICSUSPICIOUSCONNECTIONS = 379  #: Suspicious Connections
    SENSORTRAFFICNUMBEROFALERTS = 380  #: Number of Alerts
    SENSORTRAFFICNEWTCPCONNECTIONS = 381  #: New TCP Connections
    SENSORTRAFFICTCPHANDSHAKES = 382  #: TCP Handshakes
    SENSORTRAFFICCLOSEDTCPCONNECTIONS = 383  #: Closed TCP Connections
    SENSORTRAFFICTCPTIMEOUTS = 384  #: TCP Timeouts
    TRAFFICSHAPING = 385  #: TRAFFIC_SHAPING
    SHAPINGCLASS = 386  #: SHAPING_CLASS
    TOTALBYTES = 387  #: TOTAL_BYTES
    PASSEDBYTES = 388  #: PASSED_BYTES
    SHAPINGGUARANTEE = 389  #: SHAPING_GUARANTEE
    SHAPINGLIMIT = 390  #: SHAPING_LIMIT
    SHAPINGPRIORITY = 391  #: SHAPING_PRIORITY
    BALANCINGSELECTION = 392  #: BALANCING_SELECTION
    NATBALANCEID = 393  #: NAT_BALANCE_ID
    NATMAPID = 394  #: NAT_MAP_ID
    SELECTEDRTT = 395  #: SELECTED_RTT
    SELECTEDCACHE = 396  #: SELECTED_CACHE
    BALANCINGPROBING = 397  #: BALANCING_PROBING
    SRCADDRESS = 398  #: SRC_ADDRESS
    PROBEOK = 399  #: PROBE_OK
    ORIGINNAME = 400  #: Name of component producing event
    USERORIGINATOR = 401  #: Administrator causing event
    USERROLE = 402  #: Roles of Administrator causing event
    CLIENTIPADDRESS = 403  #: Address of client causing event
    TYPEDESCRIPTION = 404  #: Description of the event
    RESULT = 405  #: Result state
    #: Special field for filtering Audit entries using the defined resources.
    # Not present in the audit entries as such.
    OBJECTID = 406
    OBJECTNAME = 407  #: Elements being manipulated
    OBJECTTYPE = 408  #: Element Type
    OBJECTKEY = 409  #: Element Id
    OBJECTDN = 410  #: User and Group Information
    INCIDENTCASE = 411  #: Incident Case
    RULECOUNTERS = 412  #: RULE_COUNTERS
    RULEHITS = 413  #: RULE_HITS
    SESSIONDOMAIN = 414  #: Administrative Domain of Login Session
    ELEMENTDOMAIN = 415  #: Administrative Domain of Associated Element
    FWADSLTXBYTES = 416  #: FW_ADSL_TX_BYTES
    FWADSLRXBYTES = 417  #: FW_ADSL_RX_BYTES
    FWFORWARDEDPACKETS = 418  #: FW_FORWARDED_PACKETS
    FWFORWARDEDBYTES = 419  #: FW_FORWARDED_BYTES
    ZIPEXPORTFILE = 420  #: Snapshot of element being manipulated
    FW100TRAFFICCOUNTERS = 430  #: Fw100 Traffic counters
    FW100INTERFACE = 431  #: FW100 Interface
    WIRELESSMONITORING = 432  #: Wireless Monitoring
    WIRELESSSSID = 433  #: Wireless SSID
    WIRELESSSTATUS = 434  #: Wireless Status
    WIRELESSSECURITY = 435  #: Wireless Security mode
    WIRELESSCONNECTIONS = 436  #: Number of wireless connections
    SENSORALLOWEDINSPECTEDTCPCONNECTIONS = 437  #:
    SENSORALLOWEDINSPECTEDUDPCONNECTIONS = 438  #:
    SENSORALLOWEDUNINSPECTEDTCPCONNECTIONS = 439  #:
    SENSORALLOWEDUNINSPECTEDUDPCONNECTIONS = 440  #:
    SENSORDISCARDEDTCPCONNECTIONS = 441  #:
    SENSORDISCARDEDUDPCONNECTIONS = 442  #:
    LOGIFTOPTCPDESTINATIONPORTS = (
        443  #: Amount of traffic on the most used TCP destination ports per logical interface
    )
    LOGIFTOPUDPDESTINATIONPORTS = (
        444  #: Amount of traffic on the most used UDP destination ports per logical interface
    )
    #: Amount of traffic originating from the most used source IP addresses per logical interface
    LOGIFTOPSOURCEIPADDRS = 445
    #: Amount of traffic flowing to the most used destination IP addresses per logical interface
    LOGIFTOPDESTINATIONIPADDRS = 446
    CONNECTEDMACADDR = 447  #: Connected MAC addresses
    WIRELESSCHANNEL = 448  #: Wireless Access Point's channel
    TPTRAFFICCOUNTERS = 460  #: Third party traffic counters
    TPRECEIVEDBYTES = 461  #: TP_RECEIVED_BYTES
    TPRECEIVEDPACKETS = 462  #: TP_RECEIVED_PACKETS
    TPSENTBYTES = 463  #: TP_SENT_BYTES
    TPSENTPACKETS = 464  #: TP_SENT_PACKETS
    TPACCEPTEDBYTES = 465  #: TP_ACCEPTED_BYTES
    TPACCEPTEDPACKETS = 466  #: TP_ACCEPTED_PACKETS
    TPDROPPEDBYTES = 467  #: TP_DROPPED_BYTES
    TPDROPPEDPACKETS = 468  #: TP_DROPPED_PACKETS
    TPNODELOAD = 469  #: Third party device load
    TPMEMUSAGE = 470  #: Third party memory usage
    TAGINFO = 480  #: Type tags
    DATATAG = 481  #: Data type tag
    ALLOWEDDATATAG = 482  #: Allowed data type tag
    CONTAINEDDATATAG = 483  #: Contained data type tag
    NONCONTAINEDDATATAG = 484  #: Non-contained data type tag
    DATATAGS = 485  #: Data tags concerning the record
    RWPSERVICENAME = 831  #: SSL VPN Portal Service Name
    RWPHTTPUSERAGENT = 830  #: HTTP User Agent
    SNMPTRAPMAP = 490  #: SNMP Trap
    SNMPTRAPOID = 491  #: SNMP Trap OID
    SNMPTRAPVALUE = 492  #: SNMP Trap Value
    ENTERPRISEOID = 493  #: Enterprise OID
    GENERICTRAPTYPE = 494  #: Generic Trap Type
    DHCPLEASEPREFIXLEN = 498  #: DHCP_LEASE_PREFIXLEN
    VPNSRCID = 499  #: Source VPN
    PROBEFAIL = 500  #: PROBE_FAIL
    VPNID = 501  #: Desination VPN
    SECURITYGATEWAY = 502  #: VPN gateway
    VPNSTATUS = 503  #: VPN_STATUS
    ENDPOINT = 504  #: Local VPN end point
    PEERSECURITYGATEWAY = 505  #: Peer VPN gateway
    PEERENDPOINT = 506  #: Peer VPN end point
    VPNSTATISTICS = 507  #: VPN_STATISTICS
    VPNBYTESSENT = 508  #: VPN_BYTES_SENT
    VPNBYTESRECEIVED = 509  #: VPN_BYTES_RECEIVED
    PHASE1SUCC = 510  #: IKE_PHASE1_SUCC
    PHASE1FAIL = 511  #: IKE_PHASE1_FAIL
    PHASE2SUCC = 512  #: IKE_PHASE2_SUCC
    PHASE2FAIL = 513  #: IKE_PHASE2_FAIL
    SABUNDLE = 514  #: SA_BUNDLE
    SATYPE = 515  #: SA_TYPE
    SARESPONDER = 516  #: SA_RESPONDER
    SAINCOMING = 517  #: SA_INCOMING
    SACIPHERALG = 518  #: SA_CIPHER_ALG
    SACOMPRESSIONALG = 519  #: SA_COMPRESSION_ALG
    SAAUTHALG = 520  #: SA_AUTH_ALG
    SAKBSOFTLIMIT = 521  #: SA_KB_SOFTLIMIT
    SAKBHARDLIMIT = 522  #: SA_KB_HARDLIMIT
    SAEXPIRESOFTLIMIT = 523  #: SA_EXPIRE_SOFTLIMIT
    SAEXPIREHARDLIMIT = 524  #: SA_EXPIRE_HARDLIMIT
    SRCIPRANGE = 525  #: Source IP Range
    DSTIPRANGE = 526  #: Destination IP Range
    DHCPLEASES = 527  #: DHCP_LEASES
    DHCPLEASEEXPIRES = 528  #: DHCP_LEASE_EXPIRES
    DHCPLEASEGW = 529  #: DHCP_LEASE_GW
    DHCPLEASEIP = 530  #: DHCP_LEASE_IP
    DHCPLEASENETMASK = 531  #: DHCP_LEASE_NETMASK
    DHCPLEASERECEIVED = 532  #: DHCP_LEASE_RECEIVED
    OUTBOUNDSPI = 533  #: Outbound IPsec SPI value (hexadecimal)
    EXPIRATIONTIME = 534  #: VPN SA expiration time
    SACLASS = 535  #: SA Type
    CIPHERALG = 536  #: Cipher algorithm
    MACALG = 537  #: MAC Algorithm
    HASHALG = 538  #: Hash Algorithm
    NEGOTIATIONROLE = 539  #: SA Negotiation Role
    IKELOCALID = 540  #: Local IKE ID
    IKEREMOTEID = 541  #: Remote IKE ID
    IKEV1MODE = 542  #: IKEv1 negotiation mode
    DPD = 543  #: Dead Peer Detection
    NATT = 544  #: NAT Traversal
    TCPENCAPSULATION = 545  #: TCP Encapsulation
    IPCOMPRESSION = 546  #: IP Compression
    PFSDHGROUP = 547  #: PFS Diffie-Hellman Group
    NUMPACKETSSENT = 548  #: Number of packets sent
    NUMPACKETSRECEIVED = 549  #: Number of packets received
    AUTHENTICATIONCOUNTER = 850  #: Authentication counters
    ALERTERTRACE = 600  #: Alerter trace (events) information (datatype:4)
    LONGMSG = 601  #: Long field description of alert
    ALERTSEVERITY = 602  #: Severity of situation
    ALERTCOUNT = 603  #: Alert count
    ALERTSTATUS = 604  #: Alert status
    VPNTYPE = 611  #: VPN_TYPE
    EVENTTIME = 700  #: Time stamp of the alert
    EVENTINFO = 701  #: Description for event
    EVENTLOGID = 702  #: Data Identifier of the alert
    EVENTTYPE = 703  #: Type of event
    EVENTUSER = 704  #: User who executed the action
    EVENTADDRESS = 705  #: Notification destination
    NEIGHBORINTERFACE = 733  #: Interface
    NEIGHBORPROTOCOL = 734  #: Protocol
    NEIGHBORL3DATA = 735  #: IP Address
    NEIGHBORL2DATA = 736  #: Mac address
    NEIGHBORSTATE = 737  #: State
    LOGSEVERITY = 805  #: Severity
    SSLVPNSESSIONTYPETYPE = 808  #: SSL VPN session client type
    #: Node's local time when the SSL VPN session was created
    SSLVPNSESSIONMONRECEIVED = 809
    #: Node's local time when the SSL VPN session will time-out
    SSLVPNSESSIONMONTIMEOUT = 810
    SSLVPNSESSIONMONID = 811  #: Id of the User Session
    RADIUSACCOUNTINGTYPE = 851  #: Radius Accounting Type

    #: The identifier of the situation that caused sending this event.
    SITUATION = 1000
    HTTPREQUESTHOST = 1586  #: HTTP request host
    IKECOOKIE = 3000
    USERNAME = 3001  #: Username if present
    IDSERVICE = 3003  # The identifier of the creator of the log entry

    NUMBYTESSENT = 12200  #: Number of bytes sent, used for VPN
    NUMBYTESRECEIVED = 12201  #: Number of bytes received, used for VPN
    #: Generated from situation and original situation.
    VULNERABILITYREFERENCES = 20000
    SRCADDRS = 20007  #: Source addresses
    DSTADDRS = 20008  #: Destination addresses


class DataType:
    """
    Query by type of logs. This identifies which log types you are interested in
    filtering by, i.e. Audit, FW Logs, Third_Party, etc. Equivalent to the Query
    dropdown in the Logs view of the Management Client
    """

    IPS_LOGS = 0
    FW_LOGS = 1
    ALERTS = 3
    ALERT_EVENTS = 4
    IPS_RECORDINGS = 5
    COUNTERS = 8
    AUDIT = 9
    SSL_VPN = 28
    THIRD_PARTY = 29
    BLACKLIST_LOG = 35
    L2FW_LOGS = 36
    SSL_VPN_SESSION_MONITORING = 38
    NEIGHBOR_MONITORING = 40


class Actions:
    """
    Rule Actions
    """

    DISCARD = 0  #: Discard
    ALLOW = 1  #: Allowed
    REFUSE = 2  #: Reset
    DISCARD_PASSIVE = 4  #: Silent discard
    TERMINATE_PASSIVE = 8  #: Silent terminate
    TERMINATE = 9  #: Terminate
    TERMINATE_FAILED = 10  #: Failed terminating connection
    PERMIT = 11  #: Permit the connection
    TERMINATE_RESET = 12  #: Reset the connection
    BLOCK = 13  #: Block


class Alerts:
    """
    Alert actions
    """

    INFO = 1  #: Info alert
    LOW = 3  #: Low alert
    HIGH = 5  #: High alert
    CRITICAL = 10  #: Critical alert
