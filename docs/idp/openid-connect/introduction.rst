Introduction
============

The ``allauth.idp`` package offers an out of the box OpenID Connect provider by
means of the ``allauth.idp.protocols.openid_connect`` Django application. The
provider functionality is dependent on the base ``allauth.account`` handling,
and works seamlessly with any of the other allauth packages.

The following OpenID Connect functionality is supported:

- Authorization code grant.

- Client credentials grant.

- Implicit grant.

Functionality intentionally not supported:

- Password grant: This is a legacy flow, no longer recommended. For example, it lacks support for MFA.
