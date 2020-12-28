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

"""PyAMS_auth_oauth.zmi.provider module

This module is registering views which are used to manage OAuth providers.
"""

import json
from json import JSONDecodeError

from pyramid.events import subscriber
from pyramid.view import view_config
from zope.interface import Interface, Invalid

from pyams_auth_oauth.interfaces import IOAuthLoginConfiguration, IOAuthLoginProviderConnection
from pyams_auth_oauth.zmi.interfaces import IOauthConfigurationMenu
from pyams_form.ajax import ajax_form_config
from pyams_form.field import Fields
from pyams_form.interfaces.form import IAJAXFormRenderer, IDataExtractedEvent
from pyams_layer.interfaces import IPyAMSLayer
from pyams_pagelet.pagelet import pagelet_config
from pyams_security.interfaces import ISecurityManager, IViewContextPermissionChecker
from pyams_security.interfaces.base import MANAGE_SECURITY_PERMISSION
from pyams_site.interfaces import ISiteRoot
from pyams_skin.interfaces.viewlet import IHelpViewletManager
from pyams_skin.viewlet.actions import ContextAction
from pyams_skin.viewlet.help import AlertMessage
from pyams_table.column import GetAttrColumn
from pyams_table.interfaces import IColumn, IValues
from pyams_utils.adapter import ContextAdapter, ContextRequestViewAdapter, adapter_config
from pyams_utils.registry import get_utility
from pyams_utils.url import absolute_url
from pyams_viewlet.viewlet import viewlet_config
from pyams_zmi.form import AdminModalAddForm, AdminModalEditForm
from pyams_zmi.helper.container import delete_container_element
from pyams_zmi.helper.event import get_json_table_row_refresh_callback
from pyams_zmi.interfaces import IAdminLayer
from pyams_zmi.interfaces.table import ITableElementEditor
from pyams_zmi.interfaces.viewlet import IToolbarViewletManager
from pyams_zmi.table import I18nColumnMixin, Table, TableAdminView, TableElementEditor, \
    TrashColumn
from pyams_zmi.zmi.viewlet.menu import NavigationMenuItem


__docformat__ = 'restructuredtext'

from pyams_auth_oauth import _  # pylint: disable=ungrouped-imports


@viewlet_config(name='oauth-providers.menu',
                context=ISiteRoot, layer=IAdminLayer,
                manager=IOauthConfigurationMenu, weight=10,
                permission=MANAGE_SECURITY_PERMISSION)
class OAuthProvidersMenu(NavigationMenuItem):
    """OAuth providers menu"""

    label = _("OAuth providers")
    href = '#oauth-providers.html'


class OAuthProvidersTable(Table):
    """OAuth providers table"""

    @property
    def data_attributes(self):
        attributes = super(OAuthProvidersTable, self).data_attributes
        sm = get_utility(ISecurityManager)  # pylint: disable=invalid-name
        configuration = IOAuthLoginConfiguration(sm)
        attributes['table'].update({
            'data-ams-location': absolute_url(configuration, self.request)
        })
        return attributes


@adapter_config(required=(ISiteRoot, IAdminLayer, OAuthProvidersTable),
                provides=IValues)
class OAuthProvidersTableValues(ContextRequestViewAdapter):
    """OAuth providers table values adapter"""

    @property
    def values(self):
        """Table values"""
        sm = get_utility(ISecurityManager)  # pylint: disable=invalid-name
        yield from IOAuthLoginConfiguration(sm).values()


@adapter_config(name='id',
                required=(ISiteRoot, IAdminLayer, OAuthProvidersTable),
                provides=IColumn)
class OAuthProvidersIdColumn(I18nColumnMixin, GetAttrColumn):
    """OAuth providers ID column"""

    i18n_header = _("ID")
    attr_name = 'provider_id'

    weight = 10


@adapter_config(name='provider',
                required=(ISiteRoot, IAdminLayer, OAuthProvidersTable),
                provides=IColumn)
class OAuthProvidersProviderColumn(I18nColumnMixin, GetAttrColumn):
    """OAuth providers provider column"""

    i18n_header = _("Provider")
    attr_name = 'provider_name'

    weight = 20


@adapter_config(name='trash',
                required=(ISiteRoot, IAdminLayer, OAuthProvidersTable),
                provides=IColumn)
class OAuthProvidersTrashColumn(TrashColumn):
    """OAuth providers trash column"""


@pagelet_config(name='oauth-providers.html',
                context=ISiteRoot, layer=IPyAMSLayer,
                permission=MANAGE_SECURITY_PERMISSION, xhr=True)
class OAuthProvidersView(TableAdminView):
    """OAuth providers view"""

    table_label = _("Registered OAuth providers")
    table_class = OAuthProvidersTable


@viewlet_config(name='oauth-providers.help',
                context=ISiteRoot, layer=IAdminLayer, view=OAuthProvidersView,
                manager=IHelpViewletManager, weight=10)
class OAuthProvidersHelp(AlertMessage):
    """OAuth providers view help"""

    status = 'info'
    css_class = 'mx-2'
    _message = _("""You can provide as many OAuth connections as you want.
Each connection must have a unique integer ID.
""")


@view_config(name='delete-element.json',
             context=IOAuthLoginConfiguration, request_type=IPyAMSLayer,
             permission=MANAGE_SECURITY_PERMISSION, renderer='json', xhr=True)
def delete_oauth_provider(request):
    """OAuth provider delete view"""
    return delete_container_element(request)


@adapter_config(required=(IOAuthLoginProviderConnection, IAdminLayer, Interface),
                provides=ITableElementEditor)
class OAuthProviderElementEditor(TableElementEditor):
    """OAuth provider table element editor"""


@adapter_config(required=IOAuthLoginProviderConnection,
                provides=IViewContextPermissionChecker)
class OAuthProviderPermissionChecker(ContextAdapter):
    """OAuth provider permission checker"""

    edit_permission = MANAGE_SECURITY_PERMISSION


#
# OAuth provider views
#

@viewlet_config(name='add-oauth-provider.menu',
                context=ISiteRoot, layer=IAdminLayer,
                view=OAuthProvidersView, manager=IToolbarViewletManager, weight=10,
                permission=MANAGE_SECURITY_PERMISSION)
class OAuthProviderAddAction(ContextAction):
    """OAuth provider add action"""

    label = _("Add provider")
    status = 'success'
    icon_class = 'fas fa-plus'

    href = 'add-oauth-provider.html'
    modal_target = True

    def get_href(self):
        sm = get_utility(ISecurityManager)  # pylint: disable=invalid-name
        configuration = IOAuthLoginConfiguration(sm)
        return absolute_url(configuration, self.request, self.href)


@ajax_form_config(name='add-oauth-provider.html',
                  context=IOAuthLoginConfiguration, layer=IPyAMSLayer,
                  permission=MANAGE_SECURITY_PERMISSION)
class OAuthProviderAddForm(AdminModalAddForm):
    """OAuth provider add form"""

    title = _("Security manager")
    legend = _("Add OAuth provider")

    fields = Fields(IOAuthLoginProviderConnection).omit('__parent__', '__name__')
    content_factory = IOAuthLoginProviderConnection

    def update_content(self, obj, data):
        obj.provider_id = data.get(self, {}).get('provider_id')
        return super(OAuthProviderAddForm, self).update_content(obj, data)

    def add(self, obj):
        self.context[str(obj.provider_id)] = obj

    def next_url(self):
        return absolute_url(self.request.root, self.request, 'oauth-providers.html')


@subscriber(IDataExtractedEvent, form_selector=OAuthProviderAddForm)
def extract_oauth_provider_add_form_data(event):
    """Check new provider data"""
    data = event.data
    configuration = event.form.context
    if str(data.get('provider_id')) in configuration:
        event.form.widgets.errors += (Invalid(_("This provider ID is already used!")),)


@adapter_config(required=(IOAuthLoginConfiguration, IAdminLayer, OAuthProviderAddForm),
                provides=IAJAXFormRenderer)
class OAuthProviderAddFormRenderer(ContextRequestViewAdapter):
    """OAUth provider add form AJAX renderer"""

    def render(self, changes):
        """JSON form renderer"""
        if changes:
            return {
                'status': 'reload',
                'location': self.view.next_url()
            }
        return None


@ajax_form_config(name='properties.html',
                  context=IOAuthLoginProviderConnection, layer=IPyAMSLayer)
class OAuthProviderEditForm(AdminModalEditForm):
    """OAuth provider edit form"""

    @property
    def title(self):  # pylint: disable=missing-function-docstring
        return self.context.provider_name

    legend = _("OAuth provider properties")

    fields = Fields(IOAuthLoginProviderConnection).omit('__parent__', '__name__')


@subscriber(IDataExtractedEvent, form_selector=OAuthProviderAddForm)
@subscriber(IDataExtractedEvent, form_selector=OAuthProviderEditForm)
def extract_oauth_provider_form_data(event):
    """Check new provider data"""
    data = event.data
    headers = data.get('access_headers')
    if headers:
        try:
            json.loads(headers)
        except JSONDecodeError:
            event.form.widgets.errors += (Invalid(_("Invalid JSON data for access headers!")),)


@adapter_config(required=(IOAuthLoginProviderConnection, IAdminLayer, OAuthProviderEditForm),
                provides=IAJAXFormRenderer)
class OAuthProviderEditFormRenderer(ContextRequestViewAdapter):
    """OAuth provider edit form renderer"""

    def render(self, changes):  # pylint: disable=missing-function-docstring
        if not changes:
            return None
        provider = self.view.context
        return {
            'callbacks': [
                get_json_table_row_refresh_callback(self.request.root, self.request,
                                                    OAuthProvidersTable, provider)
            ]
        }
