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
    return LooseVersion(smc.session.api_version) >= LooseVersion(version)


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


# if check version is minor or major, corresponding smc version will be return (major/minor)
def get_smc_version(check_version):
    smc_version = smc.administration.system.System().smc_version
    if re.match(r"\d.\d+.\d", check_version):
        smc_version = '.'.join(smc_version.split()[0].split('.')[:3])
    else:
        smc_version = '.'.join(smc_version.split()[0].split('.')[:2])
    return smc_version


def is_smc_version_less_than_or_equal(check_version):
    smc_version = get_smc_version(check_version)
    return LooseVersion(smc_version) <= LooseVersion(check_version)


def is_smc_version_less_than(check_version):
    """
    check smc version url is less or not
    :param str check_version: smc version
    """
    smc_version = get_smc_version(check_version)
    return LooseVersion(smc_version) < LooseVersion(check_version)


def is_smc_version_equal(check_version):
    """
    check smc version url is equal or not.
    :param str check_version: smv version
    """
    smc_version = get_smc_version(check_version)
    return LooseVersion(smc_version) == LooseVersion(check_version)


def is_api_version_less_than_or_equal(check_version):
    return LooseVersion(smc.session.api_version) <= LooseVersion(check_version)


def is_api_version_less_than(check_version):
    return LooseVersion(smc.session.api_version) < LooseVersion(check_version)
