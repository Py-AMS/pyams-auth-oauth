#
# Copyright (c) 2015-2020 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_auth_oauth.zmi.plugin module

This modules is registering ZMI views which are used to configure OAuth authentication.
"""

__docformat__ = 'restructuredtext'

from zope.interface import Interface

from pyams_auth_oauth.zmi.interfaces import IOauthConfigurationMenu
from pyams_auth_oauth.interfaces import IOAuthSecurityConfiguration
from pyams_form.ajax import ajax_form_config
from pyams_form.browser.checkbox import SingleCheckBoxFieldWidget
from pyams_form.field import Fields
from pyams_form.interfaces.form import IGroup
from pyams_layer.interfaces import IPyAMSLayer
from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.base import MANAGE_SECURITY_PERMISSION
from pyams_security_views.zmi import ISecurityMenu
from pyams_site.interfaces import ISiteRoot
from pyams_skin.interfaces.viewlet import IHeaderViewletManager
from pyams_skin.viewlet.help import AlertMessage
from pyams_utils.adapter import adapter_config
from pyams_utils.registry import get_utility
from pyams_viewlet.manager import viewletmanager_config
from pyams_viewlet.viewlet import viewlet_config
from pyams_zmi.form import AdminEditForm, FormGroupChecker
from pyams_zmi.interfaces import IAdminLayer
from pyams_zmi.zmi.viewlet.menu import NavigationMenuItem

from pyams_auth_oauth import _  # pylint: disable=ungrouped-imports


@viewletmanager_config(name='oauth-security-configuration.menu',
                       context=ISiteRoot, layer=IAdminLayer,
                       manager=ISecurityMenu, weight=60,
                       provides=IOauthConfigurationMenu,
                       permission=MANAGE_SECURITY_PERMISSION)
class OAuthSecurityConfiguration(NavigationMenuItem):
    """OAUth security configuration menu"""

    label = _("OAuth configuration")
    href = '#oauth-security-configuration.html'


@ajax_form_config(name='oauth-security-configuration.html',
                  context=ISiteRoot, layer=IPyAMSLayer,
                  permission=MANAGE_SECURITY_PERMISSION)
class OAuthSecurityConfigurationEditForm(AdminEditForm):
    """OAUth security configuration edit form"""

    title = _("Security manager")
    legend = _("OAuth configuration")

    fields = Fields(Interface)


@adapter_config(name='oauth-configuration',
                required=(ISiteRoot, IAdminLayer, OAuthSecurityConfigurationEditForm),
                provides=IGroup)
class OAuthConfigurationGroup(FormGroupChecker):
    """OAuth configuration edit group"""

    fields = Fields(IOAuthSecurityConfiguration)
    fields['use_login_popup'].widget_factory = SingleCheckBoxFieldWidget

    def get_content(self):
        sm = get_utility(ISecurityManager)  # pylint: disable=invalid-name
        return IOAuthSecurityConfiguration(sm)


@viewlet_config(name='oauth-configuration.header',
                context=ISiteRoot, layer=IAdminLayer, view=OAuthConfigurationGroup,
                manager=IHeaderViewletManager, weight=1)
class OauthConfigurationHeader(AlertMessage):
    """Oauth configuration header"""

    status = 'info'

    _message = _("""OAuth authentication module provides features and a REST API which can be \
used to authenticate principals using external OAuth providers.

Activating this option will require additional configuration to create a dedicated users folder \
to store profiles of users which will be registered using this protocol; you will also have to \
register API keys for providers that you want to allow connection from, before recording them \
in the security manager...
""")
