Elements
========

Elements are the building blocks for policy and include types such as Networks, Hosts, 
Services, Groups, Lists, Zones, etc. 

Create
------

Elements within the Management Server are common object types that are referenced
by other configurable areas of the system such as policy, routing, VPN, etc. 

This is not an exhaustive list, all supported element types can be found in the API reference
documentation: :ref:`element-reference-label`

* *Hosts*

* *AddressRange*

* *Networks*

* *Routers*

* *Groups*

* *DomainName*

* *IPList* (SMC API >= 6.1)

* *URLListApplication* (SMC API >= 6.1)

* *Zone*

* *LogicalInterface*

* *TCPService*

* *UDPService*

* *IPService*

* *EthernetService*

* *ServiceGroup*

* *TCPServiceGroup*

* *UDPServiceGroup*

* *IPServiceGroup*

* *RPCService*

* *ICMPService*

* *ICMPv6Service*

Oftentimes these objects are cross referenced within the configuration, like when creating rule or
NAT policy.
All calls to create() will return the href of the new element stored in the Management Server database
or will raise an exception for failure.

Examples of creating elements are as follows::

	>> from smc.elements.network import Host, Network, AddressRange
	>>> host = Host.create(name='hostelement', address='1.1.1.1')
	>>> host
	Host(name=hostelement)
	>>> host.address
	u'1.1.1.1'
	>>> network = Network.create(name='networkelement', ipv4_network='1.1.1.0/24', comment='mynet')
	>>> network
	Network(name=networkelement)
	>>> network.ipv4_network
	u'1.1.1.0/24'
	>>> network.comment
	u'mynet'
	>>> AddressRange.create(name='myaddrrange', ip_range='1.1.1.1-1.1.1.10')
	AddressRange(name=myaddrrange)

Check the various reference documentation for defined elements supported.

.. _update-elements-label:

Update
------  

Updating elements can be done in multiple ways. In most cases, making modifications to an
element through methods or element attributes are the preferred way. Modifications done through
existing methods/attributes are done idempotent to the elements cache.
In order to commit these changes to the Management Server database, calling .update() is required unless
explicitly documented otherwise.

.. note:: There are some edge cases where .update() is called automatically like when modifying
	interfaces where multiple areas are updated. These will be documented on the method.

Another way to update an element is by providing the kwarg values in the update() call directly.

For example, setting the address, secondary address and comment for a host element can be
done in update by providing kwargs::

	host = Host('kali')
	host.update(
		address='3.3.3.3',
		secondary=['12.12.12.12'],
		comment='something about this host')


A much more low-level way of modifying an element is to modify the data in cache (dict)
directly. After making the modifications, you must also call .update() to submit the change.

Modifying a service element after reviewing the element cache::
   
	>>> service = TCPService.create(name='aservice', min_dst_port=9090)
	>>> service
	TCPService(name=aservice)
	...
	>>> pprint(vars(service.data))
	{u'key': 3551,
	 u'link': [{u'href': u'http://172.18.1.150:8082/6.2/elements/tcp_service/3551',
	            u'rel': u'self',
	            u'type': u'tcp_service'},
	           {u'href': u'http://172.18.1.150:8082/6.2/elements/tcp_service/3551/export',
	            u'rel': u'export'},
	           {u'href': u'http://172.18.1.150:8082/6.2/elements/tcp_service/3551/search_category_tags_from_element',
	            u'rel': u'search_category_tags_from_element'}],
	 u'min_dst_port': 9090,
	 u'name': u'aservice',
	 u'read_only': False,
	 u'system': False}
	 ...
	>>> service.data['min_dst_port'] = 9091
	>>> service.update()	# Submit to SMC, cache is refreshed
	'http://172.18.1.150:8082/6.2/elements/tcp_service/3551'
	...
	>>> pprint(vars(service.data))
	{u'key': 3551,
	 u'link': [{u'href': u'http://172.18.1.150:8082/6.2/elements/tcp_service/3551',
	            u'rel': u'self',
	            u'type': u'tcp_service'},
	           {u'href': u'http://172.18.1.150:8082/6.2/elements/tcp_service/3551/export',
	            u'rel': u'export'},
	           {u'href': u'http://172.18.1.150:8082/6.2/elements/tcp_service/3551/search_category_tags_from_element',
	            u'rel': u'search_category_tags_from_element'}],
	 u'min_dst_port': 9091,
	 u'name': u'aservice',
	 u'read_only': False,
	 u'system': False}

Attributes supported by elements are documented in the API Reference: :ref:`element-reference-label`


Delete
------

Deleting elements is done by using the base class delete method. If the element has already been fetched,
the ETag of the original fetch is stored with the element cache and will be provided during the delete.

Deleting a host::

	>>> from smc.elements.network import Host
	>>> Host('kali').delete()

Functions or methods that modify
--------------------------------

Some functions or element methods may make modifications to an element depending on the
operation. These functions are documented and will also be decorated with and ``autocommit``
decorator.
This allows you to queue changes locally before submitting them to the Management Server by calling
``update``. To override this behavior, you can either pass ``autocommit=True`` to these functions or set
``session.AUTOCOMMIT=True`` on the session. Most methods will autocommit by default with exception of
methods defined in :class:`smc.core.properties`.
