Installation
============

Install the package by using a package manager such as pip.

.. code-block:: python

   pip install fp-ngfw-smc-python

Or optionally clone: smc-python_:

.. _smc-python: https://github.com/Forcepoint/fp-NGFW-SMC-python

`python setup.py install`

Dependencies on this library are:

* requests

If installation is required on a non-internet facing machine, you will have to download
smc-python and dependencies manually and install by running python setup install.

Once the smc-python package has been installed, you can import the
main packages into a python script:

.. code-block:: python

   import smc.elements
   import smc.core.engine
   import smc.core.engines
   import smc.policy
   import smc.elements.system
   
To remove the package, simply run:

`pip uninstall fp-NGFW-SMC-python`

For more information on next steps, please see creating the session
