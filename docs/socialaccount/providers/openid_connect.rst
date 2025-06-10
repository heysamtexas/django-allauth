OpenID Connect
--------------

The OpenID Connect provider provides access to multiple independent OpenID
Connect (sub)providers. You configure these (sub)providers by adding apps to the
configuration of the overall OpenID connect provider. Each app represents a
standalone OpenID Connect provider:

.. code-block:: python

    SOCIALACCOUNT_PROVIDERS = {
        "openid_connect": {
            # Optional PKCE defaults to False, but may be required by your provider
            # Can be set globally, or per app (settings).
            "OAUTH_PKCE_ENABLED": True,
            "APPS": [
                {
                    "provider_id": "my-server",
                    "name": "My Login Server",
                    "client_id": "your.service.id",
                    "secret": "your.service.secret",
                    "settings": {
                        "server_url": "https://my.server.example.com",
                        # Optional token endpoint authentication method.
                        # May be one of "client_secret_basic", "client_secret_post"
                        # If omitted, a method from the the server's
                        # token auth methods list is used
                        "token_auth_method": "client_secret_basic",
                        "oauth_pkce_enabled": True,
                        # Optional verified_email to put the email address 
                        # from the provider as verified.
                        # If uncommmented, the email address will be fetched 
                        # from the provider's user info endpoint as verified.
                        # "verified_email": true, 
                    },
                },
                {
                    "provider_id": "other-server",
                    "name": "Other Login Server",
                    "client_id": "your.other.service.id",
                    "secret": "your.other.service.secret",
                    "settings": {
                        "server_url": "https://other.server.example.com",
                    },
                },
            ]
        }
    }

This configuration example will create two independent provider instances,
``My Login Server`` and ``Other Login Server``.

The OpenID Connect callback URL for each configured server is at
``/accounts/oidc/{id}/login/callback/`` where ``{id}`` is the configured app's
``provider_id`` value (``my-server`` or ``other-server`` in the above example).

## For Microsoft Azure Entra

For single instance of Microsoft Azure Entra, you should follow `Microsoft Graph page <microsoft.html>`__.

If you want to use Microsoft Azure Entra as an OpenID Connect provider, (possibly due to multiple Entra instances) you need to configure the following in the settings:

.. code-block:: python
    {
        "server_url": "https://login.microsoftonline.com/common/v2.0", 
        "token_auth_method": "client_secret_basic"
    }

- Make sure you change the ``common`` to your tenant id if you are using a single tenant.
- Make sure you added the ``v2.0`` to the end of the URL. Otherwise AllAuth will not receive the email address.






Authentication Request's Optional Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

See :ref:`oauth2-authentication-optional-parameters`.