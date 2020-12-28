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

"""PyAMS_auth_oauth.skin module

This module provides a login view for OAuth authentication.
Please note that this login method requires additional components provided by PyAMS_security_skin
package.
"""

from logging import WARNING

from authomatic import Authomatic
from authomatic.adapters import WebObAdapter
from pyramid.httpexceptions import HTTPBadRequest, HTTPNotFound
from pyramid.response import Response
from pyramid.security import remember
from pyramid.view import view_config
from zope.interface import Interface

from pyams_auth_oauth.interfaces import IOAuthLoginConfiguration, IOAuthSecurityConfiguration
from pyams_form.field import Fields
from pyams_form.interfaces.form import IInnerSubForm
from pyams_form.subform import InnerAddForm
from pyams_layer.interfaces import IPyAMSLayer
from pyams_security.interfaces import AuthenticatedPrincipalEvent, ISecurityManager, \
    LOGIN_REFERER_KEY
from pyams_security_views.interfaces.login import ILoginView
from pyams_template.template import template_config
from pyams_utils.adapter import adapter_config
from pyams_utils.registry import get_utility, query_utility
from pyams_viewlet.viewlet import Viewlet


__docformat__ = 'restructuredtext'


@adapter_config(name='oauth-providers.group',
                required=(Interface, IPyAMSLayer, ILoginView),
                provides=IInnerSubForm)
@template_config(template='templates/login-providers.pt', layer=IPyAMSLayer)
class OAuthProvidersGroup(InnerAddForm):
    """OAuth providers viewlet"""

    def __new__(cls, context, request, parent_form):  # pylint: disable=unused-argument
        sm = query_utility(ISecurityManager)  # pylint: disable=invalid-name
        if sm is None:
            return None
        configuration = IOAuthSecurityConfiguration(sm)
        if not configuration.enabled:
            return None
        return Viewlet.__new__(cls)

    fields = Fields(Interface)
    weight = 10

    @property
    def providers(self):
        """Get sorted OAuth providers"""
        sm = get_utility(ISecurityManager)  # pylint: disable=invalid-name
        configuration = IOAuthLoginConfiguration(sm)
        yield from sorted(configuration.values(),
                          key=lambda x: x.provider_id)


@view_config(route_name='oauth_login')
def login(request):
    """Login view for Authomatic authentication"""
    # check security manager utility
    manager = query_utility(ISecurityManager)
    if manager is None:
        raise HTTPNotFound()
    configuration = IOAuthSecurityConfiguration(manager)
    if not configuration.enabled:
        raise HTTPNotFound()
    # store referrer
    session = request.session
    if LOGIN_REFERER_KEY not in session:
        session[LOGIN_REFERER_KEY] = request.referer
    # init authomatic
    provider_name = request.matchdict.get('provider_name')
    # pylint: disable=assignment-from-no-return
    oauth_configuration = IOAuthLoginConfiguration(manager).get_oauth_configuration()
    authomatic = Authomatic(config=oauth_configuration,
                            secret=configuration.secret,
                            logging_level=WARNING)
    # perform login
    response = Response()
    result = authomatic.login(WebObAdapter(request, response), provider_name)
    if result:
        if result.error:
            pass
        elif result.user:
            if not (result.user.id and result.user.name):
                result.user.update()
                if not (result.user.id and result.user.name):
                    raise HTTPBadRequest(result.user.content)
            oauth_folder = manager.get(configuration.users_folder)
            user_id = '{provider_name}.{user_id}'.format(provider_name=provider_name,
                                                         user_id=result.user.id)
            request.registry.notify(AuthenticatedPrincipalEvent(plugin='oauth',
                                                                principal_id=user_id,
                                                                provider_name=provider_name,
                                                                user=result.user))
            principal_id = '{prefix}:{user_id}'.format(prefix=oauth_folder.prefix,
                                                       user_id=user_id)
            headers = remember(request, principal_id)
            response.headerlist.extend(headers)
        if configuration.use_login_popup:
            response.text = result.popup_html()
        response.status_code = 302
        if LOGIN_REFERER_KEY in session:
            response.location = session[LOGIN_REFERER_KEY]
            del session[LOGIN_REFERER_KEY]
        else:
            response.location = '/'
    return response
