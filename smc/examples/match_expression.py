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
Example script to show how to use MatchExpression, Expression
-check retrieve all engines
-create a match expression
-get match expression by name and by filter
-get all match expressions
-get all expressions
"""

# Python Base Import
import smc.examples

from smc import session
from smc.core.engine import Engine
from smc.elements.network import Expression
from smc.elements.service import ApplicationSituation, TCPService
from smc.policy.rule_elements import MatchExpression
from smc_info import *


if __name__ == '__main__':

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    # check for all engines
    engine_list = list(Engine.objects.all())

    # Create a match_expression
    me = MatchExpression.create(name='mymatch',
                                service=ApplicationSituation('FTP'),
                                service_ports=TCPService('Any TCP Service'))

    # Get Name for first match_expression
    name = MatchExpression.objects.iterator().first().name

    # Get by name
    print("Retrieve {} by name..".format(name))
    match_expression = MatchExpression.get(name)
    print("match_expression={}".format(match_expression))

    # Get by filter
    print("Retrieve {} by filter..".format(name))
    it = MatchExpression.objects.iterator()
    query1 = it.filter(name)
    if query1.exists():
        print("match_expression={}".format(list(query1.all())))

    # Get All match_expression
    print("")
    print("Get All match_expression...")
    for match_expression in MatchExpression.objects.all():
        print("match_expression={}".format(match_expression))
        for referenced_element in match_expression.values():
            print("ref={}".format(referenced_element))

    # Get All expression
    print("")
    print("Get All expression...")
    for expression in Expression.objects.all():
        print("expression={}".format(expression))


except Exception as e:
    print(e)
    SystemExit(-1)
finally:
    me.delete()
    session.logout()
