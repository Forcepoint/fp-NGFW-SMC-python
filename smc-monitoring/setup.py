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
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
    ],
    zip_safe=False,
    install_requires=["fp_NGFW_SMC_python >=1.0.0", "websocket-client >=0.48.0"],
)
