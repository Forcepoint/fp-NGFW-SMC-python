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

import os
import re
from io import open
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

# Version extraction inspired from 'requests'
with open(os.path.join(here, "version.py"), "r") as fd:
    version = re.search(
        r'^VERSION\s*=\s*[\'"]([^\'"]*)[\'"]',
        fd.read(),
        re.MULTILINE).group(1)

if not version:
    raise RuntimeError("Cannot find version information")

with open("README.rst", encoding="utf-8") as f:
    readme = f.read()

with open("HISTORY.rst", encoding="utf-8") as f:
    history = f.read()

setup(
    name="fp-NGFW-SMC-python-monitoring",
    version=version,
    description="Forcepoint NGFW Management Center Monitoring",
    long_description=readme + "\n\n" + history,
    license="Apache License",
    author="Forcepoint",
    author_email="PSIRT@forcepoint.com",
    url="https://github.com/Forcepoint/fp-NGFW-SMC-python",
    # packages=['smc_monitoring'],
    packages=find_packages(),
    # namespace_packages=['smc_monitoring'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
    ],
    zip_safe=False,
    install_requires=["fp_NGFW_SMC_python >=1.0.19", "websocket-client >=1.5.0"],
)
