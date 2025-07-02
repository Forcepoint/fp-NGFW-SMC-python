Introduction
============
This is the smc-python library to interface with the Forcepoint Flexedge Secure SDWAN Manager.

This acts as an front-end to simplify interactions and simplify scripting when looking
to integrate automated functionality. 

The smc-python library also has a CLI that provides a command completion syntax to provide
guidance on commands to be run, and can be run remotely from the Forcepoint Flexedge Secure SDWAN
Engines. All actions interact with the Flexedge Secure SDWAN Manager (SMC), and commands specific
to the Flexedge Secure SDWAN Engines are proxied by the Management Server component of the SMC
to the individual devices.

Current versions are validated using:

* Forcepoint NGFW Management Center >= 6.10
* Python >= 3.5
* Requests >= 2.31.0
* Websocket-client >= 1.5.0


