"""
Configuration Loader
"""
import os
import io
import json
from smc.api.exceptions import ConfigLoadError

try:
    import configparser
except ImportError:
    import ConfigParser as configparser  # @UnusedImport


def load_from_environ():
    """
    Load the SMC URL, API KEY and optional SSL certificate from
    the environment.

    Fields are::

        SMC_ADDRESS=http://1.1.1.1:8082
        SMC_API_KEY=123abc
        SMC_CLIENT_CERT=path/to/cert
        SMC_TIMEOUT = 30 (seconds)
        SMC_API_VERSION = 6.1 (optional - uses latest by default)
        SMC_DOMAIN = name of domain, Shared is default
        SMC_EXTRA_ARGS = string in dict format of extra args needed

    SMC_CLIENT CERT is only checked IF the SMC_URL is an HTTPS url.

    Example of forcing retry on service unavailable::

        os.environ['SMC_EXTRA_ARGS'] = '{"retry_on_busy": "True"}'

    """
    try:
        from urllib.parse import urlparse
    except ImportError:
        from urlparse import urlparse

    smc_address = os.environ.get("SMC_ADDRESS", "")
    smc_apikey = os.environ.get("SMC_API_KEY", "")
    smc_timeout = os.environ.get("SMC_TIMEOUT", None)
    api_version = os.environ.get("SMC_API_VERSION", None)
    domain = os.environ.get("SMC_DOMAIN", None)
    smc_extra_args = os.environ.get("SMC_EXTRA_ARGS", "")

    if not smc_apikey or not smc_address:
        raise ConfigLoadError(
            "If loading from environment variables, you must provide values "
            "SMC_ADDRESS and SMC_API_KEY."
        )

    config_dict = {}

    if smc_extra_args:
        try:
            args_as_dict = json.loads(smc_extra_args)
            config_dict.update(args_as_dict)
        except ValueError:
            pass

    config_dict.update(smc_apikey=smc_apikey)
    config_dict.update(timeout=smc_timeout)
    config_dict.update(api_version=api_version)
    config_dict.update(domain=domain)

    url = urlparse(smc_address)

    config_dict.update(smc_address=url.hostname)

    port = url.port
    if not port:
        port = "8082"

    config_dict.update(smc_port=port)

    if url.scheme == "https":
        config_dict.update(smc_ssl=True)
        ssl_cert = os.environ.get("SMC_CLIENT_CERT", None)
        if ssl_cert:  # Enable cert validation
            config_dict.update(verify_ssl=True)
            config_dict.update(ssl_cert_file=ssl_cert)
        # Else http

    return transform_login(config_dict)


def load_from_file(alt_filepath=None):
    """Attempt to read the SMC configuration from a
    dot(.) file in the users home directory. The order in
    which credentials are parsed is:

    - Passing credentials as parameters to the session login
    - Shared credential file (~/.smcrc)
    - Environment variables

    :param alt_filepath: Specify a different file name for the
           configuration file. This should be fully qualified and include
           the name of the configuration file to read.

    Configuration file should look like::

        [smc]
        smc_address=172.18.1.150
        smc_apikey=xxxxxxxxxxxxxxxxxxx
        api_version=6.1
        smc_port=8082
        smc_ssl=True
        verify_ssl=True
        retry_on_busy=True
        ssl_cert_file='/Users/username/home/mycacert.pem'

    :param str smc_address: IP of the SMC Server
    :param str smc_apikey: obtained from creating an API Client in SMC
    :param str api_version: Which version to use (default: latest)
    :param int smc_port: port to use for SMC, (default: 8082)
    :param bool smc_ssl: Whether to use SSL (default: False)
    :param bool verify_ssl: Verify client cert (default: False)
    :param bool retry_on_busy: Retry CRUD operation if service is unavailable (default: False)
    :param str ssl_cert_file: Full path to client pem (default: None)

    The only settings that are required are smc_address and smc_apikey.

    Setting verify_ssl to True (default) validates the client cert for
    SSL connections and requires the ssl_cert_file path to the cacert.pem.
    If not given, verify will default back to False.

    FQDN will be constructed from the information above.

    """
    required = ["smc_address", "smc_apikey"]
    bool_type = ["smc_ssl", "verify_ssl", "retry_on_busy"]  # boolean option flag
    option_names = [
        "smc_port",
        "api_version",
        "smc_ssl",
        "verify_ssl",
        "ssl_cert_file",
        "retry_on_busy",
        "timeout",
        "domain",
    ]

    parser = configparser.SafeConfigParser(
        defaults={
            "smc_port": "8082",
            "api_version": None,
            "smc_ssl": "false",
            "verify_ssl": "false",
            "ssl_cert_file": None,
            "timeout": None,
            "domain": None,
        },
        allow_no_value=True,
    )

    path = "~/.smcrc"

    if alt_filepath is not None:
        full_path = alt_filepath
    else:
        ex_path = os.path.expandvars(path)
        full_path = os.path.expanduser(ex_path)

    section = "smc"
    config_dict = {}
    try:
        with io.open(full_path, "rt", encoding="UTF-8") as f:
            parser.readfp(f)

        # Get required settings, if not found it will raise err
        for name in required:
            config_dict[name] = parser.get(section, name)

        for name in option_names:
            if parser.has_option(section, name):
                if name in bool_type:
                    config_dict[name] = parser.getboolean(section, name)
                else:  # str
                    config_dict[name] = parser.get(section, name)

    except configparser.NoOptionError as e:
        raise ConfigLoadError(
            "Failed loading credentials from configuration " "file: {}; {}".format(path, e)
        )
    except (configparser.NoSectionError, configparser.MissingSectionHeaderError) as e:
        raise ConfigLoadError(
            "Failed loading credential file from: {}, check the "
            "path and verify contents are correct.".format(path, e)
        )
    except IOError as e:
        raise ConfigLoadError("Failed loading configuration file: {}".format(e))

    return transform_login(config_dict)


def transform_login(config):
    """
    Parse login data as dict. Called from load_from_file and
    also can be used when collecting information from other
    sources as well.

    :param dict data: data representing the valid key/value pairs
           from smcrc
    :return: dict dict of settings that can be sent into session.login
    """
    verify = True
    if config.pop("smc_ssl", None):
        scheme = "https"

        verify = config.pop("ssl_cert_file", None)
        if config.pop("verify_ssl", None):
            # Get cert path to verify
            if not verify:  # Setting omitted or already False
                verify = False
        else:
            verify = False
    else:
        scheme = "http"
        config.pop("verify_ssl", None)
        config.pop("ssl_cert_file", None)
        verify = False

    transformed = {}
    url = "{}://{}:{}".format(scheme, config.pop("smc_address", None), config.pop("smc_port", None))

    timeout = config.pop("timeout", None)
    if timeout:
        try:
            timeout = int(timeout)
        except ValueError:
            timeout = None

    api_version = config.pop("api_version", None)
    if api_version:
        try:
            float(api_version)
        except ValueError:
            api_version = None

    transformed.update(
        url=url,
        api_key=config.pop("smc_apikey", None),
        api_version=api_version,
        verify=verify,
        timeout=timeout,
        domain=config.pop("domain", None),
    )

    if config:
        transformed.update(kwargs=config)  # Any remaining args

    return transformed
