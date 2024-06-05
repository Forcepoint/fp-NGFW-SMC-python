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
Elasticsearch Cluster

Create an Elasticsearch Cluster

        :param str name: Name of Elasticsearch Cluster
        :param list address: address of element. Can be a single FQDN or comma
        separated,list of IP addresses
        :param int port: Default port is 9200
        :param int es_retention_period: How much time logs will be kept
        30days default
        :param int es_shard_number: Auto by default, number of shards
        :param int es_replica_number : number of ES replicas
        :param bool enable_cluster_sniffer : Enable cluster sniffer (False
        default)
        :param str location: Specifies the location for the server if there
        is a NAT device between the server and other SMC components.
        :param str default_contact_address: Override default contact address
        :param str comment: Comment for Elasticsearch cluster Server element
        :param str tls_profile: tls profile name to use
        :param bool use_internal_credentials: use internal credentials
        :param str tls_credentials: tls credentials name to use

"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.certificates.tls import TLSServerCredential  # noqa
from smc.elements.servers import ElasticsearchCluster, TlsSettings  # noqa

ES_NAME = 'ES7'
ES_UPDATE_ERROR = "Failed to update ElasticsearchCluster"
ES_CREATE_ERROR = "Failed to create ElasticsearchCluster"

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
        tls_cred_5 = TLSServerCredential("Helsinki Server Protection")
        es_server = ElasticsearchCluster.create(name=ES_NAME,
                                                addresses=['1.2.3.4', 'demo.dns.net'],
                                                enable_cluster_sniffer=True,
                                                es_replica_number=10,
                                                es_retention_period=-1,
                                                es_shard_number=2,
                                                comment="ESPOWA!!!!",
                                                tls_profile="Global Sandbox TLS Profile",
                                                authentication_settings={
                                                    "method": "certificate",
                                                    "tls_credentials": tls_cred_5.href
                                                })
        es_server.add_contact_address('toto.titi.com', 'Default')
        es_server.add_contact_address('3.5.5.5', 'LocationHQ')
        assert es_server.es_replica_number == 10 and es_server.es_retention_period == -1 and \
               '1.2.3.4' in es_server.addresses and \
               es_server.es_enable_cluster_sniffer, ES_CREATE_ERROR
        logging.info("ElasticsearchCluster created successfully.")
        es_server = ElasticsearchCluster(ES_NAME)
        es_server.update(es_replica_number=11, es_retention_period=1, es_shard_number=3)
        es_server = ElasticsearchCluster(ES_NAME)
        assert es_server.es_replica_number == 11 and es_server.es_retention_period == 1 and \
               es_server.es_shard_number == 3, ES_UPDATE_ERROR
        logging.info("ElasticsearchCluster updated successfully.")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        ElasticsearchCluster(ES_NAME).delete()
        logging.info("ElasticsearchCluster deleted successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to create an Elasticsearch Cluster',
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
