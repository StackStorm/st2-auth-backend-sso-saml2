# Copyright (C) 2019 Extreme Networks, Inc - All Rights Reserved
#
# Unauthorized copying of this file, via any medium is strictly
# prohibited. Proprietary and confidential. See the LICENSE file
# included with this work for details.

import os

from setuptools import setup, find_packages

from dist_utils import check_pip_version
from dist_utils import fetch_requirements
from dist_utils import parse_version_string

check_pip_version()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS_FILE = os.path.join(BASE_DIR, 'requirements.txt')
INIT_FILE = os.path.join(BASE_DIR, 'st2auth_sso_backends', '__init__.py')

version = parse_version_string(INIT_FILE)
install_reqs, dep_links = fetch_requirements(REQUIREMENTS_FILE)

setup(
    name='st2-enterprise-sso-backend',
    version=version,
    description='Enterprise SSO backend for StackStorm.',
    author='Extreme Networks, Inc.',
    author_email='info@stackstorm.com',
    url='https://github.com/extremenetworks/st2-enterprise-sso-backend',
    license='Proprietary License',
    download_url=(
        'https://github.com/extremenetworks/st2-enterprise-sso-backend/tarball/master'
    ),
    classifiers=[
        'License :: Other/Proprietary License'
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Environment :: Console',
    ],
    platforms=['Any'],
    scripts=[],
    provides=['st2auth_sso_backends'],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_reqs,
    dependency_links=dep_links,
    test_suite='tests',
    zip_safe=False,
    entry_points={
        'st2auth.sso.backends': [
            'saml2 = st2auth_sso_backends.saml:SAML2SingleSignOnBackend'
        ]
    }
)
