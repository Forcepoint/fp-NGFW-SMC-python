"""
Example of how to create a group
"""

import smc.examples

from smc import session
from smc.elements.group import Group
from smc.elements.servers import NTPServer
from smc_info import *

FIRST_UPDATE_CREATE_COMMENT = "my first update or created group"
FIRST_UPDATE_CREATE_MEMBERS_COMMENT = "my first update or created group with members"
PREVIOUSLY_CREATED_COMMENT = "myGroup2 previously created, comment updated"
FIRST_CREATE_COMMENT = "my first create group with members"
REMOVED_MEMBERS = "myGroup3 removed members"
WRONG_COMMENT = "Wrong comment in assert!"
WRONG_MEMBERS = "Wrong members in assert!"

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    # Create NTP server to add to the group
    new_ntp_server = NTPServer().create(name="myNTPServer",
                                        comment="NTP Server created by the SMC API",
                                        address="192.168.1.200",
                                        ntp_auth_key_type="none"
                                        )

    # Create Group then add members
    grp = Group.update_or_create(name="myGroup", comment=FIRST_UPDATE_CREATE_COMMENT)
    assert grp.members == [], WRONG_MEMBERS
    grp.update_members([new_ntp_server])

    grp = Group("myGroup")
    print("comment=>{}".format(grp.comment))
    assert grp.comment == FIRST_UPDATE_CREATE_COMMENT, WRONG_COMMENT
    assert grp.members == [new_ntp_server.href], WRONG_MEMBERS

    # Create Group with members
    Group.update_or_create(name="myGroup2",
                           comment=FIRST_UPDATE_CREATE_MEMBERS_COMMENT,
                           members=[new_ntp_server])

    grp = Group("myGroup2")
    print("members=>{}".format(grp.members))
    assert grp.comment == FIRST_UPDATE_CREATE_MEMBERS_COMMENT, WRONG_COMMENT
    assert grp.members == [new_ntp_server.href], WRONG_MEMBERS

    # Update existing myGroup2
    Group.update_or_create(name="myGroup2",
                           comment=PREVIOUSLY_CREATED_COMMENT,
                           members=[new_ntp_server])

    grp = Group("myGroup2")
    print("updated comment=>{}, members={}".format(grp.comment, grp.members))
    assert grp.comment == PREVIOUSLY_CREATED_COMMENT, WRONG_COMMENT
    assert grp.members == [new_ntp_server.href], WRONG_MEMBERS

    # Create Group using create method
    Group.create(name="myGroup3",
                 comment=FIRST_CREATE_COMMENT,
                 members=[new_ntp_server])

    grp = Group("myGroup3")
    print("comment={}, members=>{}".format(grp.comment, grp.members))
    assert grp.comment == FIRST_CREATE_COMMENT, WRONG_COMMENT
    assert grp.members == [new_ntp_server.href], WRONG_MEMBERS

    # Update myGroup3 remove members
    Group.update_or_create(name="myGroup3",
                           comment=REMOVED_MEMBERS,
                           remove_members=True,
                           members=[new_ntp_server])
    grp = Group("myGroup3")
    print("comment={}, members=>{}".format(grp.comment, grp.members))
    assert grp.comment == REMOVED_MEMBERS, WRONG_COMMENT
    assert grp.members == [], WRONG_MEMBERS

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    Group("myGroup").delete()
    Group("myGroup2").delete()
    Group("myGroup3").delete()
    NTPServer("myNTPServer").delete()
    session.logout()
