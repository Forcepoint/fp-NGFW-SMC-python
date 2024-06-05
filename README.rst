|Python version|

smc-python
==========

Python based library to provide the ability to interact with the
Forcepoint NGFW Management Center API. Provides automation capabilities
for any environment that interact with the SMC remotely.

Some of the functionality you get with the SMC Python API:

-  Create any engine types; single firewall, cluster firewalls, ips
   engines, layer 2 firewalls, master engine and virtual engines.
-  Engine operations such as enabling/disabling AV, GTI, default NAT,
   Contact Addresses, etc
-  Interface configurations
-  Routing configurations (OSPF, BGP, Static, Antispoofing)
-  Engine level commands such as rebooting, going offline, policy push,
   enable/disable SSH, etc.
-  Create and modify all network element objects such as Host, Network,
   Address Ranges, Domain Names, etc.
-  Policy control (create rules, delete rules) for layer 3 firewall
   policies
-  VPN Policy control and creation
-  Management / Log Server settings configuration
-  Admin User creation and modification
-  System level controls; update system packages, update engines, global
   blacklisting, etc
-  Tasks
-  Search operations for any object type by name, href and by filter
-  Collections interface to view all objects by type

Requirements
------------

Python >= 2.7 or >= 3.5

Requests >= 2.31.0
websocket-client >= 1.5.0

Security Management Center version >= 6.0

Getting Started
---------------

Installing package

From git:

``pip install git+https://github.com/Forcepoint/fp-NGFW-SMC-python.git``

Or after cloning:

``python setup.py install``

Testing
-------

Included are a variety of test example scripts that leverage the API to
do various tasks in `smc/examples <https://github.com/Forcepoint/fp-NGFW-SMC-python/tree/master/smc/examples>`__ directory

Basics
------

Before any commands are run, you must obtain a login session. Once
commands are complete, call `session.logout()` to remove the active session.
To obtain the api\_key, log in to the Forcepoint NGFW Management Center and
create an API client with the proper privileges.

.. code:: python

    from smc import session

    session.login(url='http://1.1.1.1:8082', api_key='xxxxxxxxxxxxx')
    ....do stuff....
    session.logout()

Or log in to a specific Admin Domain and use a specific version of the
API:

.. code:: python

    session.login(url='http://1.1.1.1:8082', api_key='xxxxxxxxxxxxx',
                  domain=mydomain, api_version=6.2)
    ....do stuff....
    session.logout()

Once a valid session is obtained, it will be re-used for each operation
for the duration of the sessions validity, or until the program is
exited.

Extensions
**********

Extensions are available to smc-python that provide additional functionality besides what
is provided in the base library. Extensions are kept separate as they may require additional
package requirements and simplify packaging.

Available extensions:

* `smc-python-monitoring <https://badge.fury.io/py/fp-NGFW-SMC-python-monitoring>`__: Monitoring for SMC connections, blacklists, users, VPNs, alerts, etc. In addition this package provides the ability to 'subscribe' to administrative event modifications.

Extensions are found in the base smc-python repository as namespace packages and each is housed in it's own sub-directory of this base package.

Pull Requests
*************

Pull requests are accepted and welcome but they could not be merged as are.
Indeed, we are using internal repository in order to validate and integrate these changes.
But they could be released later on following our road map.

Commit Message Guidelines
*************************

We follow a consistent commit message format to maintain a clear and organized version history. This helps in understanding the purpose of each commit and tracking changes effectively.

Each and every commit message to the repository must follow this format.

.. code:: text

    <jira_key>: <title>
    <body>

- Jira Key: Jira Ticket ID or Key that begins with "SMC-".

- Title: Usually the title of the Jira ticket, or a concise version of the same.

- Body: Additional details about the commit. Use this section to provide more context and information if necessary.

Example:

.. code:: text

    SMC-51100: CI Validation
    - Check that commit starts with "SMC-"
    - Update Jira tickets automatically

Documentation
-------------

`View Documentation on Read The Docs <http://fp-ngfw-smc-python.readthedocs.io/en/latest/?badge=latest>`__

.. |Python version| image:: https://img.shields.io/badge/python-2.7%20%7C%203.5%20%7C%203.6-blue
    :target: https://pypi.python.org/pypi/fp-NGFW-SMC-python/
