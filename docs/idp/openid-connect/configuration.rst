Configuration
=============

Available settings:

``IDP_OPENID_CONNECT_ACCESS_TOKEN_EXPIRES_IN`` (default: 3600)
  The time (in seconds) after which access tokens expire.

``IDP_OPENID_CONNECT_ADAPTER`` (default: ``"allauth.idp.protocols.openid_connect.adapter.DefaultOpenIDConnectAdapter"``)
  Specifies the adapter class to use, allowing you to alter certain
  default behavior.

``AUTHORIZATION_CODE_EXPIRES_IN`` (default: 60)
  The time (in seconds) after which authorization codes expire.

``IDP_OPENID_CONNECT_PRIVATE_KEY`` (default: ``""``)
  The private key used for creating ID tokens (and ``.well-known/jwks.json``).

``IDP_OPENID_CONNECT_ID_TOKEN_EXPIRES_IN`` (default: 300)
  The time (in seconds) after which ID tokens expire.
