"""
Example script to show system properties usage.
"""

# Python Base Import

# Python SMC Import
import smc.examples

from smc import session
from smc.administration.system import System
from smc_info import *

new_ebanner_text_value = 'Welcome in SMC!'
ebanner_text_system_key = 55
ebanner_text_name = 'export_banner_text'
get_ebanner_error_msg = '{} system_key does not point to {} global system property but on {}.'
update_ebanner_error_msg = '{} system property has not been set correctly: {}. It should have {}.'

if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")

    try:
        system = System()

        for system_property in system.system_properties():
            print("system_property= {}".format(system_property))

        print("Retrieve {} system property from "
              "its system_key ({})...".format(ebanner_text_name, ebanner_text_system_key))
        ebanner_text_property = system.system_property(system_key=ebanner_text_system_key)
        assert ebanner_text_property.name == ebanner_text_name,\
            get_ebanner_error_msg.format(ebanner_text_system_key,
                                         ebanner_text_name, ebanner_text_property.name)

        print("Update {} system property...".format(ebanner_text_name))
        system.update_system_property(system_key=ebanner_text_system_key,
                                      new_value=new_ebanner_text_value)

        print("Check the update {} system property...".format(ebanner_text_name))
        ebanner_text_property = system.system_property(system_key=ebanner_text_system_key)

        assert ebanner_text_property.value == new_ebanner_text_value,\
            update_ebanner_error_msg.format(ebanner_text_name,
                                            ebanner_text_property.value, new_ebanner_text_value)

    except Exception as e:
        print("Error:{}".format(e))
        exit(-1)
    finally:
        session.logout()
