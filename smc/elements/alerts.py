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
Alert element types that can be used as a matching criteria in the rules of an Alert Policy.
"""
from smc.base.model import Element, ElementCreator


class AlertElement(Element):
    """
    Base alert element.
    """


class CustomAlert(AlertElement):
    """
    This represents a custom Alert.
    It gives the name and description to an Alert Event. The Alert element can be used
    as a matching criteria in the rules of an Alert Policy.

    Create an alert::

        CustomAlert.create('myalert')
    """

    typeof = "alert"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create the custom alert

        :param str name: name of custom alert
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta
        :rtype: CustomAlert
        """
        json = {"name": name, "comment": comment}

        return ElementCreator(cls, json)


class FwAlert(AlertElement):
    """
    This represents a predefined Firewall Alert.
    It gives the name and description to an Alert Event. The Alert element can be used
    as a matching criteria in the rules of an Alert Policy.
    """

    typeof = "fw_alert"


class IdsAlert(AlertElement):
    """
    This represents a predefined IDS Alert.
    It gives the name and description to an Alert Event. The Alert element can be used
    as a matching criteria in the rules of an Alert Policy.
    """

    typeof = "ids_alert"
