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

"""PyAMS OAuth authentication package interfaces module

"""

from zope.annotation import IAttributeAnnotatable
from zope.container.constraints import containers, contains
from zope.interface import Attribute, Interface, Invalid, invariant
from zope.schema import Bool, Choice, Datetime, Int, List, Text, TextLine

from pyams_security.interfaces import IDirectorySearchPlugin


__docformat__ = 'restructuredtext'

from pyams_auth_oauth import _


OAUTH_CONFIGURATION_KEY = 'pyams_auth_oauth.configuration'
"""Main OAuth configuration key"""

OAUTH_LOGIN_CONFIGURATION_KEY = 'pyams_auth_oauth.providers'
"""OAuth providers configuration key"""

OAUTH_USERS_FOLDERS_VOCABULARY_NAME = 'pyams_auth_oauth.folders'
"""OAuth users folders vocabulary name"""

OAUTH_PROVIDERS_VOCABULARY_NAME = 'pyams_auth_oauth.providers'
"""OAuth providers vocabulary name"""


#
# OAuth authentication utility interface
#

class IOAuthSecurityConfiguration(Interface):
    """Security manager configuration interface for OAuth"""

    enabled = Bool(title=_("Enable OAuth login?"),
                   description=_("Enable login via OAuth authentication"),
                   required=False,
                   default=False)

    users_folder = Choice(title=_("OAuth users folder"),
                          description=_("Name of folder used to store properties of users "
                                        "authenticated with OAuth"),
                          required=False,
                          vocabulary=OAUTH_USERS_FOLDERS_VOCABULARY_NAME)

    @invariant
    def check_users_folder(self):
        """Check for OAuth configuration"""
        if self.enabled and not self.users_folder:
            raise Invalid(_("You can't activate OAuth login without selecting an OAuth users "
                            "folder"))

    secret = TextLine(title=_("Authomatic secret"),
                      description=_("This secret phrase is used to encrypt Authomatic "
                                    "cookie"),
                      default='this is not a secret',
                      required=True)

    use_login_popup = Bool(title=_("Use OAuth popup?"),
                           description=_("If 'yes', a connection popup will be used"),
                           required=True,
                           default=False)


#
# OAuth login providers configuration
#

class IOAuthLoginProviderInfo(Interface):
    """OAuth login provider info

    This interface is used to adapt providers to
    get minimum information like icon class, URLs
    required to get consumer elements...
    """

    name = TextLine(title="Provider name")

    provider = Attribute("Provider class")

    icon_class = TextLine(title="Icon class",
                          description="Fontawesome icon class",
                          required=True)

    icon_filename = TextLine(title="Color icon filename",
                             required=True)

    scope = List(title="User info scope",
                 value_type=TextLine())


class IOAuthLoginConfiguration(Interface):
    """OAuth login configuration interface"""

    contains('pyams_auth_oauth.interfaces.IOAuthLoginProviderConnection')

    def get_oauth_configuration(self):
        """Get Authomatic configuration"""


class IOAuthLoginProviderConnection(Interface):
    """OAuth login provider info"""

    containers(IOAuthLoginConfiguration)

    provider_id = Int(title=_("Provider ID"),
                      description=_("This value should be unique between all providers"),
                      required=True,
                      readonly=True,
                      min=0)

    provider_name = Choice(title=_("Provider name"),
                           vocabulary=OAUTH_PROVIDERS_VOCABULARY_NAME,
                           required=True)

    consumer_key = TextLine(title=_("Provider consumer key"),
                            description=_("This consumer key is given by your OAuth provider..."),
                            required=True)

    consumer_secret = TextLine(title=_("Provider secret"),
                               description=_("This secret key is given by your OAuth "
                                             "provider..."),
                               required=True)

    access_headers = Text(title=_("Access headers"),
                          description=_("Some providers require custom headers; you can enter "
                                        "them in JSON format..."),
                          required=False)

    def get_configuration(self):
        """Get provider configuration"""


#
# OAuth users interfaces
#

class IOAuthUsersFolderPlugin(IDirectorySearchPlugin):
    """OAuth users folder interface"""

    contains('pyams_auth_oauth.interfaces.IOAuthUser')


class IOAuthUser(IAttributeAnnotatable):
    """OAuth user interface"""

    containers(IOAuthUsersFolderPlugin)

    user_id = TextLine(title=_("Internal provider ID"))

    provider_name = TextLine(title=_("OAuth provider name"))

    username = TextLine(title=_("User name"),
                        required=False)

    name = TextLine(title=_("Name"))

    first_name = TextLine(title=_('First name'),
                          required=False)

    last_name = TextLine(title=_('Last name'),
                         required=False)

    nickname = TextLine(title=_('Nickname'),
                        required=False)

    email = TextLine(title=_("E-mail address"),
                     required=False)

    timezone = TextLine(title=_('Timezone'),
                        required=False)

    country = TextLine(title=_('Country'),
                       required=False)

    city = TextLine(title=_('City'),
                    required=False)

    postal_code = TextLine(title=_("Postal code"),
                           required=False)

    locale = TextLine(title=_('Locale code'),
                      required=False)

    picture = TextLine(title=_('Picture URL'),
                       required=False)

    birth_date = Datetime(title=_('Birth date'),
                          required=False)

    registration_date = Datetime(title=_("Registration date"),
                                 readonly=True)
