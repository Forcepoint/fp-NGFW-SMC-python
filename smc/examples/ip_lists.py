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
Example script to create an empty IP List, create an IPList with contents provided as
a python list, download an IP List in a specified format (txt, json or zip),
and upload an IP List.

IP Lists are a new network element supported in SMC API and engines at version 6.1 or newer.
These allow for individual IP addresses or network addresses, one per line, and can be used
in the source/destination fields of an engine policy.

IPList operations are done by downloading the existing IPList (after creation), modifying
the list contents and uploading back to SMC.

.. note:: Contents of the uploaded IPList will replace the existing contents of the IPList
          with the same name on the SMC.

For upload, a content-type of
multipart/form-data is required with the exception of modifying an IPList as json. The
header type setting is handled by smc-python automatically.

File format for the IPList is::

    1.1.1.0/24
    2.2.2.2
    3.3.3.3
    4.4.4.4
    5.5.5.5
    6.6.6.1-6.6.6.254
    aaaa:bbbb::cccc
    aaaa:bbbb::/32
    aaaa:bbbb::
    ...

Requirements:
* smc-python >= 0.5.0
* Forcepoint NGFW Management Center >= 6.2

"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.network import IPList  # noqa

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def upload_as_zip(name, filename):
    """
    Upload an IPList as a zip file. Useful when IPList is very large.
    This is the default upload format for IPLists.

    :param str name: name of IPList
    :param str filename: name of zip file to upload, full path
    :return: None
    """
    location = list(IPList.objects.filter(name))
    if location:
        iplist = location[0]
        return iplist.upload(filename=filename)


def upload_as_text(name, filename):
    """
    Upload the IPList as text from a file.

    :param str name: name of IPList
    :param str filename: name of text file to upload
    :return: None
    """
    location = list(IPList.objects.filter(name))
    if location:
        iplist = location[0]
        return iplist.upload(filename=filename, as_type="txt")


def upload_as_json(name, mylist):
    """
    Upload the IPList as json payload.

    :param str name: name of IPList
    :param list: list of IPList entries
    :return: None
    """
    location = list(IPList.objects.filter(name))
    if location:
        iplist = location[0]
        return iplist.upload(json=mylist, as_type="json")


def download_as_zip(name, filename):
    """
    Download IPList with zip compression. Recommended for IPLists
    of larger sizes. This is the default format for downloading
    IPLists.

    :param str name: name of IPList
    :param str filename: name of filename for IPList
    """
    location = list(IPList.objects.filter(name))
    if location:
        iplist = location[0]
        return iplist.download(filename=filename)


def download_as_text(name, filename):
    """
    Download IPList as text to specified filename.

    :param str name: name of IPList
    :param str filename: name of file for IPList download
    """
    location = list(IPList.objects.filter(name))
    if location:
        iplist = location[0]
        return iplist.download(filename=filename, as_type="txt")


def download_as_json(name):
    """
    Download IPList as json. This would allow for easily
    manipulation of the IPList, but generally recommended only for
    smaller lists

    :param str name: name of IPList
    :return: None
    """
    location = list(IPList.objects.filter(name))
    if location:
        iplist = location[0]
        return iplist.download(as_type="json")


def create_iplist(name):
    """
    Create an empty IPList as name

    :param str name: name of IPList
    :return: href of list location
    """
    iplist = IPList.create(name=name)
    return iplist


def create_iplist_with_data(name, iplist):
    """
    Create an IPList with initial list contents.

    :param str name: name of IPList
    :param list iplist: list of IPList IP's, networks, etc
    :return: href of list location
    """
    iplist = IPList.create(name=name, iplist=iplist)
    return iplist


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")
        # Create initial list
        result = create_iplist_with_data(name="mylist", iplist=["123.123.123.123", "23.23.23.23"])
        logging.info(f"This is the href location for the newly created list: {result.href}")

        logging.info(download_as_text('mylist', filename='/tmp/iplist.txt'))

        logging.info(download_as_zip('mylist', filename='/tmp/iplist.zip'))

        upload_as_text('mylist', '/tmp/iplist.txt')

        upload_as_json('mylist', {'ip': ['1.1.1.1', '2.2.2.2', '3.3.3.3']})
        logging.info(download_as_json('mylist'))

        upload_as_zip('mylist', '/tmp/iplist.zip')
        logging.info(download_as_json('mylist'))

        logging.info(create_iplist(name='newlist'))
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        logging.info("delete elements..")
        IPList("mylist").delete()
        IPList("newlist").delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use IP Lists',
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
