Zitadel
-------

The Zitadel provider is OAuth2 based.

More info:
    https://zitadel.com/docs/guides/integrate/login/oidc

App registration (get your key and secret here)
    Create a new application in your Zitadel Console under your project

Development callback URL
    http://127.0.0.1:8000/accounts/zitadel/login/callback/

Configure your Zitadel instance URL and application credentials:

.. code-block:: python

    SOCIALACCOUNT_PROVIDERS = {
        'zitadel': {
            'ZITADEL_BASE_URL': 'https://your-instance.zitadel.cloud',
            'SCOPE': ['openid', 'profile', 'email', 'offline_access'],
        }
    }

ZITADEL_BASE_URL:
    The base URL of your Zitadel instance. For Zitadel Cloud, this will be in the
    format ``https://your-instance.zitadel.cloud``. For self-hosted instances,
    use your custom domain.

SCOPE:
    The default scopes are ``openid``, ``profile``, ``email``, and ``offline_access``.
    You can customize these based on your application's requirements.

In your Zitadel Console:

1. Navigate to your project and click "New" in the Applications section
2. Choose "Web" as the application type
3. Select "Authorization Code" as the authentication method
4. Add your callback URL: ``http://127.0.0.1:8000/accounts/zitadel/login/callback/`` for development
5. Note the Client ID and Client Secret from the application details

The app credentials are configured for your Django installation via the admin
interface. Create a new socialapp through ``/admin/socialaccount/socialapp/``.

Fill in the form as follows:

* Provider, "Zitadel"
* Name, your pick, suggest "Zitadel"
* Client id, is called "ClientId" by Zitadel
* Secret key, is called "ClientSecret" by Zitadel
* Key, is not needed, leave blank.
