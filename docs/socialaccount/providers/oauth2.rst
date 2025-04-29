OAuth 2.0
---------

The implementation of the OAuth 2.0 provider is used for

- :doc:`tumblr_oauth2`
- :doc:`twitter_oauth2`
- :doc:`vimeo_oauth2`
- :doc:`openid_connect`
  - :doc:`keycloak`

.. _oauth2-authentication-optional-parameters:

Authentication Request's Optional Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Optional parameters can be provided as a dictionary under the key ``auth_params``.

.. attention::

    Some providers might not support each of these parameters.

.. code-block:: python

    SOCIALACCOUNT_PROVIDERS = {
        "oauth2": {
            "APPS": [
                {
                    "provider_id": "my-server",
                    "name": "My Login Server",
                    "client_id": "your.service.id",
                    "secret": "your.service.secret",
                    "settings": {
                        "server_url": "https://my.server.example.com",
                        "auth_params": {
                          "prompt": "login",
                        }
                    },
                },
            ]
        }
    }

This configuration example will tell the provider instance, ``My Login Server``,
to prompt the user for reauthentication.