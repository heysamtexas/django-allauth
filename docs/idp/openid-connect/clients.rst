Clients
=======

The Open ID Connect clients (also commonly referred to as consumers, or applications) can be managed via the Django admin. A typical client configuration has the following properties:

ID
    The client ID. This field is automatically populated.

Secret
    The client secret. This field is automatically populated. Note that you use encrypted
    secrets by providing your own ``encrypt()`` / ``decrypt()`` adapter methods.

Scopes
    The scope(s) the client is allowed to request. Values are provide line by line, e.g.::

      openid
      profile
      email

Grant types
    A list of allowed grant types. Provide one value per line, e.g.::

      authorization_code
      client_credentials
      refresh_token

Redirect URIs
    A list of allowed redirect (callback) URLs, one per line.

Response types
    A list of allowed response types. Provide one value per line, e.g.::

      code

Skip consent
    When enabled, the consent page is silently skipped and all requested scopes are granted.

Type
    Confidential clients are clients that are able to securely authenticate with
    the authorization server as they are able to keep their registered client
    secret safe. Public clients, such as applications running in a browser or
    mobile device, are unable to keep the client secrets safe.
