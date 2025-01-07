#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
Example to show how to use an url list application
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.network import URLListApplication, ApplicationPort  # noqa
from smc.elements.service import IPService  # noqa

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")
        # Create Url list application with default application port
        URLListApplication().create(name="myUrlList_default",
                                    url_entry=["www.foo.com", "www.bar.com"])

        url_list = URLListApplication("myUrlList_default")
        for ap in url_list.application_port:
            logging.info(f"application_port={ap}")
        logging.info(f"url_entry={url_list.url_entry}")

        # update url entry
        url_list.url_entry = ["www.new-entry.com"]
        url_list.update()

        url_list = URLListApplication("myUrlList_default")
        logging.info(f"url_entry={url_list.url_entry}")

        # Create Url list application
        application_port1 = ApplicationPort(port_from=443,
                                            port_to=443,
                                            protocol_ref=IPService("TCP").href,
                                            tls="free")
        URLListApplication().create(name="myUrlList",
                                    url_entry=["www.foo.com", "www.bar.com"],
                                    application_ports=[application_port1])

        url_list = URLListApplication("myUrlList")
        for ap in url_list.application_port:
            logging.info(f"application_port={ap}")
        logging.info(f"url_entry={url_list.url_entry}")

        application_port2 = ApplicationPort(port_from=8080,
                                            port_to=8080,
                                            protocol_ref=IPService("TCP").href,
                                            tls="no")
        url_list.add_application_port(application_ports=[application_port2])

        url_list = URLListApplication("myUrlList")
        for ap in url_list.application_port:
            logging.info(f"application_port={ap}")

    except BaseException as e:
        logging.error(f"ex={e}")
        return_code = 1
    finally:
        URLListApplication("myUrlList_default").delete()
        URLListApplication("myUrlList").delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use an url list application',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    parser.add_argument(
        '--api-url',
        type=str,
        help='SMC API url like https://192.168.1.1:8082')
    parser.add_argument(
        '--api-version',
        type=str,
        help='The API version to use for run the script'
    )
    parser.add_argument(
        '--smc-user',
        type=str,
        help='SMC API user')
    parser.add_argument(
        '--smc-pwd',
        type=str,
        help='SMC API password')
    parser.add_argument(
        '--api-key',
        type=str, default=None,
        help='SMC API api key (Default: None)')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == '__main__':
    sys.exit(main())
