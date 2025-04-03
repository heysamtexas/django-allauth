from datetime import timedelta
from typing import List

from django.contrib.auth import get_user_model
from django.utils import timezone

import jwt
from oauthlib.openid import RequestValidator

from allauth.account.internal.userkit import user_id_to_str
from allauth.core import context
from allauth.idp.protocols.openid_connect.internal.clientkit import (
    is_redirect_uri_allowed,
)
from allauth.idp.protocols.openid_connect.internal.oauthlib import (
    authorization_codes,
)
from allauth.idp.protocols.openid_connect.models import Client, Token


class MyRequestValidator(RequestValidator):

    def validate_client_id(self, client_id: str, request):
        client = Client.objects.filter(id=client_id).first()
        if not client:
            return False
        request.client = client
        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return is_redirect_uri_allowed(redirect_uri, request.client.get_redirect_uris())

    def validate_response_type(
        self, client_id, response_type, client, request, *args, **kwargs
    ):
        return response_type in request.client.get_response_types()

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return set(scopes).issubset(request.client.get_scopes())

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return []

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        authorization_codes.create(client_id, code, request)

    def authenticate_client(self, request, *args, **kwargs):
        # FIXME: basic auth?
        client_id = getattr(request, "client_id", None)
        client_secret = getattr(request, "client_secret", None)
        if not isinstance(client_id, str) or not isinstance(client_secret, str):
            return False
        client = Client.objects.filter(id=client_id).first()
        if not client:
            return False
        # FIXME: check secret
        request.client = client
        request.client.client_id = client_id
        return True

    def validate_grant_type(
        self, client_id, grant_type, client, request, *args, **kwargs
    ):
        return grant_type in client.get_grant_types()

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        return authorization_codes.validate(client_id, code, request)

    def confirm_redirect_uri(
        self, client_id, code, redirect_uri, client, request, *args, **kwargs
    ):
        authorization_code = authorization_codes.lookup(client_id, code)
        if not authorization_code:
            return False
        return redirect_uri == authorization_code["redirect_uri"]

    def save_bearer_token(self, token: dict, request, *args, **kwargs):
        """Persist the Bearer token.

        The Bearer token should at minimum be associated with:
            - a client and it's client_id, if available
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)
            - an expiration time
            - a refresh token, if issued
            - a claims document, if present in request.claims

        The Bearer token dict may hold a number of items::

            {
                'token_type': 'Bearer',
                'access_token': 'askfjh234as9sd8',
                'expires_in': 3600,
                'scope': 'string of space separated authorized scopes',
                'refresh_token': '23sdf876234',  # if issued
                'state': 'given_by_client',  # if supplied by client (implicit ONLY)
            }

        Note that while "scope" is a string-separated list of authorized scopes,
        the original list is still available in request.scopes.

        The token dict is passed as a reference so any changes made to the dictionary
        will go back to the user.  If additional information must return to the client
        user, and it is only possible to get this information after writing the token
        to storage, it should be added to the token dictionary.  If the token
        dictionary must be modified but the changes should not go back to the user,
        a copy of the dictionary must be made before making the changes.

        Also note that if an Authorization Code grant request included a valid claims
        parameter (for OpenID Connect) then the request.claims property will contain
        the claims dict, which should be saved for later use when generating the
        id_token and/or UserInfo response content.

        :param token: A Bearer token dict.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: The default redirect URI for the client

        Method is used by all core grant types issuing Bearer tokens:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant (might not associate a client)
            - Client Credentials grant
        """
        tokens = [
            Token(
                client=request.client,
                user=request.user,
                type=Token.Type.ACCESS_TOKEN,
                value=token["access_token"],
                expires_at=timezone.now() + timedelta(seconds=token["expires_in"]),
            )
        ]
        refresh_token = token.get("refresh_token")
        if refresh_token:
            tokens.append(
                Token(
                    client=request.client,
                    user=request.user,
                    type=Token.Type.REFRESH_TOKEN,
                    value=refresh_token,
                )
            )
        Token.objects.bulk_create(tokens)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        authorization_codes.invalidate(client_id, code)

    def validate_user_match(self, id_token_hint, scopes, claims, request):
        if id_token_hint:
            # FIXME
            raise NotImplementedError
        if claims:
            sub = claims.get("sub")
            if sub:
                # FIXME
                raise NotImplementedError
        return True

    def get_authorization_code_scopes(
        self, client_id, code, redirect_uri, request
    ) -> List[str]:
        authorization_code = authorization_codes.lookup(client_id, code)
        return authorization_code["scopes"]

    def get_authorization_code_nonce(self, client_id, code, redirect_uri, request):
        authorization_code = authorization_codes.lookup(client_id, code)
        return "FIXME"

    def finalize_id_token(self, id_token: dict, token: dict, token_handler, request):
        id_token["sub"] = user_id_to_str(request.user)
        id_token["iss"] = context.request.build_absolute_uri("/").rstrip("/")
        id_token["exp"] = id_token["iat"] + 5 * 60  # FIXME: hardcoded
        return jwt.encode(id_token, key="FIXME")

    def validate_bearer_token(self, token, scopes, request) -> bool:
        instance = (
            Token.objects.valid()
            .filter(type=Token.Type.ACCESS_TOKEN, value=token)
            .first()
        )
        if not instance:
            return False
        request.user = instance.user
        return True

    def get_userinfo_claims(self, request):
        # FIXME
        return {"sub": user_id_to_str(request.user)}
