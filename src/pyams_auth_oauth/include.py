#
# Copyright (c) 2015-2019 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS OAuth authentication package include module

This module is used for Pyramid integration.
"""


__docformat__ = 'restructuredtext'


def include_package(config):
    """Pyramid package include"""

    # add translations
    config.add_translation_dirs('pyams_auth_oauth:locales')

    # add login route
    config.add_route('oauth_login', '/api/auth/oauth/{provider_name}')

    try:
        import pyams_zmi  # pylint: disable=import-outside-toplevel,unused-import
        config.scan()
    except ImportError:
        config.scan(ignore='pyams_auth_oauth.zmi')
