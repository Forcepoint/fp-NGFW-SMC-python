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
The DEBUG log of a request and of its response carries the secret attributes of the elements
(SMTP password, OAuth client secret, authentication key) masked, whatever the element holding
them, while the bodies actually sent and received are left alone.
"""
import json
import logging
import unittest
from unittest import mock

from smc.api import web


def smtp_body():
    return {
        "name": "mail",
        "authentication_password": "p@ss",
        "oauth_client_secret": "s3cret",
        "nested": [{"password": "deep", "comment": "kept"}],
    }


class RedactedBodyTest(unittest.TestCase):

    def test_secret_attributes_are_masked_at_any_depth(self):
        logged = json.loads(web.redacted_body(json.dumps(smtp_body())))
        self.assertEqual(web.REDACTED, logged["authentication_password"])
        self.assertEqual(web.REDACTED, logged["oauth_client_secret"])
        self.assertEqual(web.REDACTED, logged["nested"][0]["password"])

    def test_other_attributes_are_kept(self):
        logged = json.loads(web.redacted_body(json.dumps(smtp_body())))
        self.assertEqual("mail", logged["name"])
        self.assertEqual("kept", logged["nested"][0]["comment"])

    def test_a_bytes_body_is_decoded_first(self):
        logged = web.redacted_body(json.dumps(smtp_body()).encode("utf-8"))
        self.assertNotIn("p@ss", logged)

    def test_a_body_that_is_not_json_is_logged_as_it_is(self):
        self.assertEqual("name=value", web.redacted_body("name=value"))

    def test_no_body_stays_none(self):
        self.assertIsNone(web.redacted_body(None))

    def test_the_body_the_caller_holds_is_not_modified(self):
        # Masking happens in place on the copy decoded for the log, never on what is sent.
        sent = smtp_body()
        web.redacted_body(json.dumps(sent))
        self.assertEqual("p@ss", sent["authentication_password"])


class DebugLogTest(unittest.TestCase):

    def test_neither_the_request_nor_the_response_leaks_a_secret(self):
        response = mock.Mock(url="https://smc/mail", status_code=200, headers={})
        response.request = mock.Mock(method="POST", headers={}, body=json.dumps(smtp_body()))
        response.text = json.dumps(smtp_body())
        with self.assertLogs(web.logger, level=logging.DEBUG) as captured:
            web.debug(response)
        output = "\n".join(captured.output)
        for secret in ("p@ss", "s3cret", "deep"):
            self.assertNotIn(secret, output)
        self.assertIn(web.REDACTED, output)


if __name__ == "__main__":
    unittest.main()
