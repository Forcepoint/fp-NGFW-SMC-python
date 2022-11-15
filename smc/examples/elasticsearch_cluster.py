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
import smc.examples

from smc import session
from smc.elements.servers import ElasticsearchCluster
from smc_info import *


if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

    try:
        es_server = ElasticsearchCluster.create(name='ES7',
                                                addresses=['1.2.3.4', 'demo.dns.net'],
                                                enable_cluster_sniffer=True,
                                                es_replica_number=10,
                                                es_retention_period=-1,
                                                es_shard_number=2,
                                                comment="ESPOWA!!!!",
                                                tls_profile="APAC Sandbox TLS "
                                                            "Profile",
                                                use_internal_credentials=True)
        es_server.add_contact_address('toto.titi.com', 'Default')
        es_server.add_contact_address('3.5.5.5', 'LocationHQ')

    except BaseException as e:
        print("ex={}".format(e))
        exit(-1)
    finally:
        ElasticsearchCluster("ES7").delete()
        session.logout()
