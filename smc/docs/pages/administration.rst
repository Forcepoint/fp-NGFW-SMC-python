Administration
--------------

Administration provides an interface to system level administration tasks such as
creating administrators, updating the SMC with dynamic updates, updating NGFW Engines with engine
upgrades, running tasks, etc.

Administrators
++++++++++++++

Creating administrators and modifying settings can be done using the 
:py:class:`smc.elements.user.AdminUser` class.

For example, to create a user called 'administrator' and modify after creation, do:

Create admin:

.. code-block:: python

   AdminUser.create('administrator')
    
To modify after creation by setting a password and making a superuser:

.. code-block:: python

   admin = AdminUser('administrator') # Load an admin user called administrator
   admin.change_password('mynewpassword')
   admin.update(superuser=True) # ad-hoc update of attribute
   admin.enable_disable() #enable or disable account

Tasks
+++++

Tasks may be generated by methods within certain classes, for example, many
classes support an export() method. This is an asynchronous task that generates a 
'follower' link to the task. 

It is possible to monitor those asynchronous operations seperately from the direct
method call by getting the follower href and using :py:class:`smc.actions.tasks.TaskMonitor`
or :py:class:`smc.actions.tasks.TaskDownload` classes.

For example, fire off a policy update on an engine and get the asynchronous follower href:

.. code-block:: python

   engine = Engine('myfw')
   task_follower = engine.refresh(wait_for_finish=True) #This isn't required as engine will still refresh
   while not task_follower.done():
       task_follower.wait(3)
   print("Did task succeed: %s" % task_follower.success)
   print("Last message from task: %s" % task_follower.last_message)
   

System
++++++

System level tasks include operations such as checking for and downloading a new
dynamic update, engine upgrades, last activated package, SMC version, SMC time, 
emptying the trash bin, viewing all license details, importing, exporting 
elements and submitting global blacklist entries.

To view any available update packages:

.. code-block:: python
   
	from smc.administration.system import System

	system = System()
    available_packages = system.update_package() 
    print(list(available_packages))
 
To fully download and activate a dynamic update::

	system = System()
	available_packages = system.update_package() 
    
    my_dynup = available_packages.get_contains('1097')
    
    if my_dynup.state.lower() == 'available':
        download_task = my_dynup.download(wait_for_finish=True)
        while not download_task.done():
            download_task.wait(3)
            print(download_task.last_message())
        if download_task.success:
            print("Success!")
    
    # We are now downloaded, so activate
    activation = my_dynup.activate(wait_for_finish=True)
    while not activation.done():
        activation.wait(3)
        print(activation.last_message())
    
    if activation.success:
        print("We are now activated")
    else:
        print("Something bad went wrong: %s" % activation.last_message())

 
Empty the trash bin:

.. code-block:: python

   system = System()
   system.empty_trash_bin()
