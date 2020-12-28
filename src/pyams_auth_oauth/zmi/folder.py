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

"""PyAMS_auth_oauth.zmi.folder module

This module holds views used to manage OAuth users folders.
"""

from pyramid.view import view_config
from zope.interface import Interface

from pyams_auth_oauth.interfaces import IOAuthUser, IOAuthUsersFolderPlugin
from pyams_auth_oauth.plugin import get_provider_info
from pyams_form.ajax import ajax_form_config
from pyams_form.field import Fields
from pyams_layer.interfaces import IPyAMSLayer
from pyams_pagelet.pagelet import pagelet_config
from pyams_security.interfaces import ISecurityManager, IViewContextPermissionChecker
from pyams_security.interfaces.base import MANAGE_SECURITY_PERMISSION
from pyams_security_views.zmi import ISecurityManagerView
from pyams_security_views.zmi.plugin import SecurityPluginAddForm, SecurityPluginAddMenu, \
    SecurityPluginPropertiesEditForm
from pyams_site.interfaces import ISiteRoot
from pyams_table.column import GetAttrColumn
from pyams_table.interfaces import IColumn, IValues
from pyams_utils.adapter import ContextAdapter, ContextRequestViewAdapter, adapter_config
from pyams_utils.date import EXT_DATETIME_FORMAT
from pyams_utils.url import absolute_url
from pyams_viewlet.viewlet import viewlet_config
from pyams_zmi.form import AdminModalDisplayForm
from pyams_zmi.helper.container import delete_container_element
from pyams_zmi.interfaces import IAdminLayer
from pyams_zmi.interfaces.table import ITableElementEditor
from pyams_zmi.interfaces.viewlet import IContextAddingsViewletManager
from pyams_zmi.search import SearchForm, SearchResultsView, SearchView
from pyams_zmi.table import DateColumn, I18nColumnMixin, IconColumn, Table, TableElementEditor, \
    TrashColumn


__docformat__ = 'restructuredtext'

from pyams_auth_oauth import _  # pylint: disable=ungrouped-imports


@viewlet_config(name='add-oauth-folder-plugin.menu',
                context=ISiteRoot, layer=IAdminLayer, view=ISecurityManagerView,
                manager=IContextAddingsViewletManager, weight=50,
                permission=MANAGE_SECURITY_PERMISSION)
class OAuthFolderPluginAddMenu(SecurityPluginAddMenu):
    """OAuth folder plug-in add menu"""

    label = _("Add OAuth users folder...")
    href = 'add-oauth-folder-plugin.html'


@ajax_form_config(name='add-oauth-folder-plugin.html',
                  context=ISecurityManager, layer=IPyAMSLayer,
                  permission=MANAGE_SECURITY_PERMISSION)
class OAuthFolderPluginAddForm(SecurityPluginAddForm):
    """OAuth folder plug-in add form"""

    legend = _("Add OAuth users folder plug-in")
    content_factory = IOAuthUsersFolderPlugin


@ajax_form_config(name='properties.html',
                  context=IOAuthUsersFolderPlugin, layer=IPyAMSLayer)
class OAuthFolderPropertiesEditForm(SecurityPluginPropertiesEditForm):
    """OAuth folder plug-in properties edit form"""

    title = _("OAuth users folder plug-in")
    plugin_interface = IOAuthUsersFolderPlugin


#
# OAuth users folder search view
#

class OAuthUsersSearchForm(SearchForm):  # pylint: disable=abstract-method
    """OAuth users search form"""

    title = _("Users search form")

    @property
    def back_url(self):
        """URL to previous page"""
        return absolute_url(self.request.root, self.request, 'security-plugins.html')


@pagelet_config(name='search.html',
                context=IOAuthUsersFolderPlugin, layer=IPyAMSLayer,
                permission=MANAGE_SECURITY_PERMISSION)
class OAuthUsersSearchView(SearchView):
    """OAuth users search view"""

    title = _("Users search form")
    search_form = OAuthUsersSearchForm


class OAuthUsersSearchResultsTable(Table):
    """OAuth users search results table"""

    @property
    def data_attributes(self):
        attributes = super(OAuthUsersSearchResultsTable, self).data_attributes
        attributes['table'].update({
            'data-ams-order': '1,asc'
        })
        return attributes


@adapter_config(required=(IOAuthUsersFolderPlugin, IAdminLayer, OAuthUsersSearchResultsTable),
                provides=IValues)
class OAuthUsersSearchResultsValues(ContextRequestViewAdapter):
    """OAuth users search results values"""

    @property
    def values(self):
        """Search results values"""
        yield from self.context.get_search_results({
            'query': self.request.params.get('form.widgets.query')
        })


@adapter_config(name='provider',
                required=(IOAuthUsersFolderPlugin, IAdminLayer, OAuthUsersSearchResultsTable),
                provides=IColumn)
class OAuthUsersSearchProviderColumn(IconColumn):
    """OAuth users search provider column"""

    weight = 10

    def get_icon_class(self, item):
        provider_info = get_provider_info(item.provider_name)
        if provider_info is not None:
            return provider_info.icon_class
        return 'fa fa-question-circle'

    def get_icon_hint(self, item):
        provider_info = get_provider_info(item.provider_name)
        if provider_info is not None:
            return provider_info.name
        return None


@adapter_config(name='name',
                required=(IOAuthUsersFolderPlugin, IAdminLayer, OAuthUsersSearchResultsTable),
                provides=IColumn)
class OAuthUsersSearchNameColumn(I18nColumnMixin, GetAttrColumn):
    """OAuth users search name column"""

    i18n_header = _("Name")
    attr_name = 'name'
    default_value = '--'

    weight = 20


@adapter_config(name='email',
                required=(IOAuthUsersFolderPlugin, IAdminLayer, OAuthUsersSearchResultsTable),
                provides=IColumn)
class OAuthUsersSearchEmailColumn(I18nColumnMixin, GetAttrColumn):
    """OAuth users search email column"""

    i18n_header = _("Mail address")
    attr_name = 'email'
    default_value = '--'

    weight = 30


@adapter_config(name='registration_date',
                required=(IOAuthUsersFolderPlugin, IAdminLayer, OAuthUsersSearchResultsTable),
                provides=IColumn)
class OAuthUsersSearchRegistrationDateColumn(I18nColumnMixin, DateColumn):
    """OAuth users search registration date column"""

    i18n_header = _("Registration date")
    attr_name = 'registration_date'
    formatter = EXT_DATETIME_FORMAT

    weight = 50


@adapter_config(name='trash',
                required=(IOAuthUsersFolderPlugin, IAdminLayer, OAuthUsersSearchResultsTable),
                provides=IColumn)
class OAuthUsersSearchTrashColumn(TrashColumn):
    """OAuth users search trash column"""


@pagelet_config(name='search-results.html',
                context=IOAuthUsersFolderPlugin, layer=IPyAMSLayer,
                permission=MANAGE_SECURITY_PERMISSION, xhr=True)
class OAuthUsersSearchResultsView(SearchResultsView):
    """OAuth users search results view"""

    table_label = _("Search results")
    table_class = OAuthUsersSearchResultsTable


@view_config(name='delete-element.json',
             context=IOAuthUsersFolderPlugin, request_type=IPyAMSLayer,
             permission=MANAGE_SECURITY_PERMISSION, renderer='json', xhr=True)
def delete_local_user(request):
    """Local user delete view"""
    return delete_container_element(request)


#
# OAuth users views
#

@ajax_form_config(name='properties.html', context=IOAuthUser, layer=IPyAMSLayer)
class OAuthUserEditForm(AdminModalDisplayForm):
    """OAuth user display form"""

    @property
    def title(self):
        """Form title"""
        return self.context.name or '{} {}'.format(self.context.first_name,
                                                   self.context.last_name)

    legend = _("User properties")

    fields = Fields(IOAuthUser).omit('__parent__', '__name__')


@adapter_config(required=(IOAuthUser, IAdminLayer, Interface),
                provides=ITableElementEditor)
class OAuthUserEditor(TableElementEditor):
    """OAuth users editor"""


@adapter_config(required=IOAuthUser, provides=IViewContextPermissionChecker)
class OAuthUserPermissionChecker(ContextAdapter):
    """OAuth user permission checker"""

    edit_permission = MANAGE_SECURITY_PERMISSION
