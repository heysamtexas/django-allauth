Configuration
=============

Available settings:

``IDP_OPENID_CONNECT_ADAPTER`` (default: ``"allauth.idp.protocols.openid_connect.adapter.DefaultOpenIDConnectAdapter"``)
  Specifies the adapter class to use, allowing you to alter certain
  default behavior.

``IDP_OPENID_CONNECT_PRIVATE_KEYS`` (default: ``[]``)
  The private key.

``IDP_OPENID_CONNECT_ID_TOKEN_EXP`` (default: 300)
  The expiry time (in seconds) after which ID tokens expire.
