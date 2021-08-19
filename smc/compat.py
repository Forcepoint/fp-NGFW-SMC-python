"""
Compatibility for py2 / py3
"""
import sys
import smc
import re
from distutils.version import LooseVersion

PY3 = sys.version_info > (3,)

if PY3:
    string_types = (str,)
else:
    string_types = (basestring,)

if PY3:
    unicode = str
else:
    unicode = unicode

PYTHON_v3_9 = sys.version_info >= (3, 9)


def min_smc_version(version):
    """
    Is version at least the minimum provided
    Used for compatibility with selective functions
    """
    return float(smc.session.api_version) >= version


def get_best_version(*versions):
    """
    Given a list of (version, value) pairs this function will return the
    value best suited for the current api version. Use this with key name
    changes between API versions.

    Ex.
        ElementList(('6.5', 'ref'),('6.6', 'network_ref'))
    """
    versions = list(versions)
    sorted_versions = sorted(versions, key=lambda t: LooseVersion(t[0]))
    best_value = sorted_versions[0][1]

    for version, value in sorted_versions:
        if LooseVersion(version) > LooseVersion(smc.session.api_version):
            break
        best_value = value

    return best_value


def is_smc_version_less_than_or_equal(check_version):
    smc_version = smc.administration.system.System().smc_version
    smc_version = '.'.join(smc_version.split()[0].split('.')[:2])
    return LooseVersion(smc_version) <= LooseVersion(check_version)


def is_api_version_less_than_or_equal(check_version):
    return LooseVersion(smc.session.api_version) <= LooseVersion(check_version)
