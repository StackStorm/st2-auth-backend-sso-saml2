# -*- coding: utf-8 -*-
# Copyright (C) 2019 Extreme Networks, Inc - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential.
# See the LICENSE file included with this work for details.

from __future__ import absolute_import

import os
import re
import sys

from distutils.version import StrictVersion

# NOTE: This script can't rely on any 3rd party dependency so we need to use this code here
PY3 = sys.version_info[0] == 3

if PY3:
    text_type = str
else:
    text_type = unicode  # NOQA

GET_PIP = 'curl https://bootstrap.pypa.io/get-pip.py | python'

__all__ = [
    'check_pip_is_installed',
    'check_pip_version',
    'fetch_requirements',
    'apply_vagrant_workaround',
    'get_version_string',
    'parse_version_string'
]


def check_pip_is_installed():
    """
    Ensure that pip is installed.
    """
    try:
        import pip  # NOQA
    except ImportError as e:
        print('Failed to import pip: %s' % (text_type(e)))
        print('')
        print('Download pip:\n%s' % (GET_PIP))
        sys.exit(1)

    return True


def check_pip_version(min_version='6.0.0'):
    """
    Ensure that a minimum supported version of pip is installed.
    """
    check_pip_is_installed()

    import pip

    if StrictVersion(pip.__version__) < StrictVersion(min_version):
        print("Upgrade pip, your version '{0}' "
              "is outdated. Minimum required version is '{1}':\n{2}".format(pip.__version__,
                                                                            min_version,
                                                                            GET_PIP))
        sys.exit(1)

    return True


def fetch_requirements(requirements_file_path):
    """
    Return a list of requirements and links by parsing the provided requirements file.
    """
    links = []
    reqs = []

    def _get_link(line):
        vcs_prefixes = ['git+', 'svn+', 'hg+', 'bzr+']

        for vcs_prefix in vcs_prefixes:
            if line.startswith(vcs_prefix) or line.startswith('-e %s' % (vcs_prefix)):
                req_name = re.findall('.*#egg=(.+)([&|@]).*$', line)

                if not req_name:
                    req_name = re.findall('.*#egg=(.+?)$', line)
                else:
                    req_name = req_name[0]

                if not req_name:
                    raise ValueError('Line "%s" is missing "#egg=<package name>"' % (line))

                link = line.replace('-e ', '').strip()
                return link, req_name[0]

        return None, None

    with open(requirements_file_path, 'r') as fp:
        for line in fp.readlines():
            line = line.strip()

            if line.startswith('#') or not line:
                continue

            link, req_name = _get_link(line=line)

            if link:
                links.append(link)
            else:
                req_name = line

            reqs.append(req_name)

    return (reqs, links)


def apply_vagrant_workaround():
    """
    Function which detects if the script is being executed inside vagrant and if it is, it deletes
    "os.link" attribute.
    Note: Without this workaround, setup.py sdist will fail when running inside a shared directory
    (nfs / virtualbox shared folders).
    """
    if os.environ.get('USER', None) == 'vagrant':
        del os.link


def get_version_string(init_file):
    """
    Read __version__ string for an init file.
    """

    with open(init_file, 'r') as fp:
        content = fp.read()
        version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                                  content, re.M)
        if version_match:
            return version_match.group(1)

        raise RuntimeError('Unable to find version string in %s.' % (init_file))


# alias for get_version_string
parse_version_string = get_version_string
