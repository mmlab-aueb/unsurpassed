# -*- coding: utf-8 -*-
from __future__ import with_statement
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

__license__ = """
    This file is part of Dedalus.

    Dedalus is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Dedalus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Dedalus.  If not, see <http://www.gnu.org/licenses/>.
"""

__author__ = 'Esmerald Aliaj'
__email__ = 'esmeraldaliai@yahoo.gr'

options = {}

with open('README.md') as fp:
    README = fp.read().strip() + "\n\n"

ChangeLog = (
    "What's new\n"
    "==========\n"
    "\n")
with open('ChangeLog') as fp:
    ChangeLog += fp.read().strip()

LONG_DESCRIPTION = README + ChangeLog
CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'Intended Audience :: System Administrators',
    'Environment :: Plugins',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: Communications',
    'Topic :: Internet',
    'Topic :: System :: Networking',
    'License :: OSI Approved :: BSD License',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
]

exec(open('src/_version.py').read())
from dedalus._version import __version__
# TODO: this line fixed an error with __version__ however I'm not sure if it should be here
# TODO: install iperf3
setup(
    name='Dedalus',
    version=__version__,
    packages=['dedalus'],
    # package_dir={'dedalus': 'Dedalus'},
    url='https://github.com/',
    download_url='https://github.com/',
    license='LGPLv3',
    author='Esmerald Aliaj',
    install_requires=['msgpack-python', 'zmq', 'pyyaml'],
    author_email='esmeraldaliai@yahoo.gr',
    maintainer="esmerald",
    maintainer_email="esmeraldaliai@yahoo.gr",
    description='A collection of broker, workers, and clients that can be used in an Adhoc network in order to '
                'retrieve and display real time statistics',
    long_description=LONG_DESCRIPTION,
    zip_safe=False,
    use_2to3=True,
    keywords="security statistics adhoc networks",
    classifiers=CLASSIFIERS
)
