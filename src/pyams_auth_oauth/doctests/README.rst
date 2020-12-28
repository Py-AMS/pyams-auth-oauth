==================================
PyAMS OAuth authentication package
==================================


Introduction
============

This package is an extension to PyAMS_security, which provides features to authenticate
principals using external OAuth or OpenID providers (like Facebbok, Google, Twitter and many
others).

The package relies on Python "Authomatic" package.

    >>> import pprint

    >>> from pyramid.testing import tearDown, DummyRequest
    >>> from pyams_security.tests import setup_tests_registry, new_test_request
    >>> from pyramid.threadlocal import manager
    >>> config = setup_tests_registry()
    >>> config.registry.settings['zodbconn.uri'] = 'memory://'

    >>> from pyramid_zodbconn import includeme as include_zodbconn
    >>> include_zodbconn(config)
    >>> from pyams_utils import includeme as include_utils
    >>> include_utils(config)
    >>> from pyams_site import includeme as include_site
    >>> include_site(config)
    >>> from pyams_security import includeme as include_security
    >>> include_security(config)
    >>> from pyams_auth_oauth import includeme as include_auth_oauth
    >>> include_auth_oauth(config)

    >>> from pyams_site.generations import upgrade_site
    >>> request = DummyRequest()
    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS security to generation 2...

    >>> from zope.traversing.interfaces import BeforeTraverseEvent
    >>> from pyramid.threadlocal import manager
    >>> from pyams_utils.registry import handle_site_before_traverse
    >>> handle_site_before_traverse(BeforeTraverseEvent(app, request))
    >>> manager.push({'request': request, 'registry': config.registry})


Using PyAMS security policy
---------------------------

The plugin should be included correctly into PyAMS security policy:

    >>> from pyramid.authorization import ACLAuthorizationPolicy
    >>> config.set_authorization_policy(ACLAuthorizationPolicy())

    >>> from pyams_security.policy import PyAMSAuthenticationPolicy
    >>> policy = PyAMSAuthenticationPolicy(secret='my secret',
    ...                                    http_only=True,
    ...                                    secure=False)
    >>> config.set_authentication_policy(policy)

    >>> from pyams_security.interfaces import ISecurityManager
    >>> from pyams_utils.registry import get_utility
    >>> sm = get_utility(ISecurityManager)
    >>> sm
    <...SecurityManager object at 0x...>


Using OAuth authentication
--------------------------

You can activate OAuth authentication by using the Authomatic package, which provides support
for OAuth1 and OAuth2 protocols.

There are several steps required to activate this: you must first register your site or application
on at least one OAuth authentication provider, which will give you a public and a private tokens;
then, register these provider settings into the security manager, and create a "OAuth users
folder", which will be used to store properties of principals which have been authenticated with
an OAuth provider; and finally, activate these settings into the security manager:

    >>> from pyams_utils.factory import register_factory
    >>> from pyams_auth_oauth.interfaces import IOAuthSecurityConfiguration
    >>> from pyams_auth_oauth.plugin import OAuthSecurityConfiguration
    >>> register_factory(IOAuthSecurityConfiguration, OAuthSecurityConfiguration)

    >>> from pyams_auth_oauth.plugin import OAuthLoginProviderConnection
    >>> github_provider = OAuthLoginProviderConnection()
    >>> github_provider.provider_name = 'github'
    >>> github_provider.provider_id = 1
    >>> github_provider.consumer_key = 'this-is-my-consumer-key'
    >>> github_provider.consumer_secret = 'this-is-my-consumer-secret'

    >>> login_info = github_provider.get_configuration()
    >>> login_info
    <pyams_auth_oauth.plugin.OAuthLoginProviderInfo object at 0x...>
    >>> login_info.name
    'GitHub'
    >>> login_info.provider
    <class 'authomatic.providers.oauth2.GitHub'>

    >>> from pyams_auth_oauth.interfaces import IOAuthLoginConfiguration
    >>> from pyams_auth_oauth.plugin import OAuthLoginConfiguration
    >>> register_factory(IOAuthLoginConfiguration, OAuthLoginConfiguration)

    >>> login_configuration = IOAuthLoginConfiguration(sm)
    >>> login_configuration['github'] = github_provider

    >>> from pyams_auth_oauth.plugin import OAuthUsersFolder
    >>> oauth_folder = OAuthUsersFolder()
    >>> oauth_folder.prefix = 'oauth'
    >>> oauth_folder.title = 'OAuth principals'
    >>> sm['oauth'] = oauth_folder

    >>> oauth_folder in sm.credentials_plugins
    False
    >>> oauth_folder in sm.authentication_plugins
    False
    >>> oauth_folder in sm.directory_plugins
    True

    >>> configuration = IOAuthSecurityConfiguration(sm)
    >>> configuration.users_folder = oauth_folder.__name__
    >>> configuration.enabled = False

When everything is enabled, we can accept authentication by using an external OAuth provider.

    >>> from pyams_auth_oauth.skin import login as oauth_login
    >>> login_request = DummyRequest(path='/api/login/oauth/github', referer='/',
    ...                              matchdict={'provider_name': 'github'})
    >>> login_result = oauth_login(login_request)
    Traceback (most recent call last):
    ...
    pyramid.httpexceptions.HTTPNotFound: The resource could not be found.

    >>> configuration.enabled = True
    >>> login_result = oauth_login(login_request)
    >>> login_result
    <Response at 0x... 302 Found>
    >>> login_result.location
    'https://github.com/login/oauth/authorize...client_id=this-is-my-consumer-key...'
    >>> login_result.headers.get('Set-Cookie')
    'authomatic=...; Domain=example.com; Path=; HttpOnly'

We can now simulate an Authomatic provider response:

    >>> from unittest.mock import MagicMock
    >>> from authomatic import Authomatic
    >>> from authomatic.core import User
    >>> from authomatic.providers.oauth2 import GitHub

    >>> class LoginUser:
    ...     id = 'github_user_id'
    ...     name = 'Jon Doe'
    ...     def __getattr__(self, item):
    ...         return self.__dict__.get(item, None)

    >>> class LoginResponse:
    ...     error = None
    ...     user = LoginUser()
    ...     popup_html = lambda x: '<div>This is HTML response</div>'
    >>> Authomatic.login = MagicMock(return_value=LoginResponse())

    >>> configuration.use_login_popup = True
    >>> login_result = oauth_login(login_request)
    >>> login_result
    <Response at 0x... 302 Found>
    >>> login_result.location
    '/'
    >>> login_result.text
    '<div>This is HTML response</div>'

So the login request first returns a redirect response to OAuth provider URL; after correct
authentication, a new OAuth principal is created into OAuth users folder; this new principal
will be usable as any local user, to affect roles for example.

As we can't rely on this provider, we will "simulate" a correct login:

    >>> class Result:
    ...     def __init__(self, user):
    ...         self.user = user
    >>> result = Result(User('github',
    ...                      user_id='123456',
    ...                      username='john.doe',
    ...                      name='John Doe'))

    >>> from pyams_security.interfaces import AuthenticatedPrincipalEvent
    >>> event = AuthenticatedPrincipalEvent('oauth',
    ...                                     principal_id='github_user_id',
    ...                                     provider_name='github',
    ...                                     user=result.user)

    >>> from pyams_auth_oauth.plugin import handle_authenticated_oauth_principal
    >>> handle_authenticated_oauth_principal(event)

    >>> user = oauth_folder.get('github_user_id')
    >>> user
    <pyams_auth_oauth.plugin.OAuthUser object at 0x...>
    >>> user.user_id
    'github_user_id'
    >>> user.provider_name
    'github'
    >>> user.title
    'John Doe'
    >>> user.title_with_source
    'John Doe (Github)'

    >>> from pyams_security.interfaces.base import IPrincipalInfo
    >>> principal = IPrincipalInfo(user)
    >>> principal
    <pyams_security.principal.PrincipalInfo object at 0x...>
    >>> principal.id
    'oauth:github_user_id'
    >>> principal.title
    'John Doe'

We can now use OAuth's users folder methods to search users:

    >>> oauth_folder.get_principal('admin:admin') is None
    True
    >>> oauth_folder.get_principal('oauth:missing') is None
    True

    >>> oauth_folder.get_principal(principal.id)
    <pyams_security.principal.PrincipalInfo object at 0x...>
    >>> oauth_folder.get_principal(principal.id, info=False) is user
    True

    >>> oauth_folder.get_all_principals(None)
    set()
    >>> oauth_folder.get_all_principals('oauth:missing')
    set()
    >>> oauth_folder.get_all_principals(principal.id)
    {'oauth:github_user_id'}

    >>> list(oauth_folder.find_principals(None))
    []
    >>> list(oauth_folder.find_principals('oauth:missing'))
    []
    >>> list(oauth_folder.find_principals('john'))
    [<pyams_security.principal.PrincipalInfo object at 0x...>]

    >>> list(oauth_folder.get_search_results({}))
    []
    >>> list(oauth_folder.get_search_results({'query': 'john'}))
    [<pyams_auth_oauth.plugin.OAuthUser object at 0x...>]

We can also use security manager methods:

    >>> sm.find_principals('john')[0] is principal
    False
    >>> sm.find_principals('john')[0] == principal
    True


We can disable users folder:

    >>> oauth_folder.enabled = False
    >>> oauth_folder.get_principal(principal.id) is None
    True
    >>> oauth_folder.get_all_principals(principal.id)
    set()
    >>> list(oauth_folder.find_principals('john'))
    []


OAuth security traversal
------------------------

    >>> from zope.traversing.interfaces import ITraversable
    >>> traverser = config.registry.queryAdapter(sm, ITraversable, name='oauth-config')
    >>> config = traverser.traverse('')
    >>> config
    <pyams_auth_oauth.plugin.OAuthLoginConfiguration object at 0x...>
    >>> config is login_configuration
    True


Tests cleanup:

    >>> from pyams_utils.registry import set_local_registry
    >>> set_local_registry(None)
    >>> manager.clear()
    >>> tearDown()
