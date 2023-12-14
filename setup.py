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
from setuptools import setup, find_packages
from codecs import open

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, 'smc', '__version__.py'), 'r', 'utf-8') as f:
    exec(f.read(), about)
        
if '__version__' not in about:
    raise RuntimeError('Cannot find version information')

with open('README.rst', encoding='utf-8') as f:
    readme = f.read()
    
with open('HISTORY.rst', encoding='utf-8') as f:
    history = f.read()

    
setup(name='fp-NGFW-SMC-python',
      version=about['__version__'],
      description=about['__description__'],
      long_description=readme + '\n\n' + history,
      url=about['__url__'],
      author=about['__author__'],
      author_email=about['__author_email__'],
      license=about['__license__'],
      packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
      install_requires=[
        'requests>=2.31.0',
        'pytz>=2022.6',
        'urllib3>=1.26.18'
      ],
      include_package_data=True,
      classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License"
        ],
      zip_safe=False)
