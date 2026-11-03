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
Regression guard: a request built with headers=None, as the IP list zip
download does, must still carry the session token.
"""
import unittest
from unittest import mock

from smc.api.common import SMCRequest


class SMCRequestHeadersTest(unittest.TestCase):

    def test_token_added_to_request_built_without_headers(self):
        session = mock.Mock(_token="token-1")
        request = SMCRequest(href="https://smc/ip_address_list", headers=None)
        with mock.patch("smc.api.common._get_session", return_value=session), \
                mock.patch("smc.api.common.send_request", return_value="result") as send:
            self.assertEqual("result", request.read())
        self.assertEqual({"Authorization": "token-1"}, send.call_args[0][2].headers)


if __name__ == "__main__":
    unittest.main()
