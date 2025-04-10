import uuid
from datetime import timedelta
from typing import List

from django.utils import timezone

import jwt
from oauthlib.openid import RequestValidator

from allauth.account.models import EmailAddress
from allauth.account.utils import user_username
from allauth.core import context
from allauth.core.internal import jwkkit
from allauth.idp.protocols.openid_connect import app_settings
from allauth.idp.protocols.openid_connect.adapter import get_adapter
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
        # WORKAROUND: docstring says:
        # > To support OIDC, you MUST associate the code with:
        # > - nonce, if present (``code["nonce"]``)
        # Yet, nonce is not there, it is in request.nonce.
        nonce = getattr(request, "nonce", None)
        if nonce:
            code = dict(**code, nonce=nonce)
        # (end WORKAROUND)
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
        if client.get_secret() != client_secret:
            return False
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
        adapter = get_adapter()
        tokens = [
            Token(
                client=request.client,
                user=request.user,
                type=Token.Type.ACCESS_TOKEN,
                hash=adapter.hash_token(token["access_token"]),
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
                    hash=adapter.hash_token(refresh_token),
                )
            )
        Token.objects.bulk_create(tokens)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        authorization_codes.invalidate(client_id, code)

    def validate_user_match(self, id_token_hint, scopes, claims, request):
        if not context.request.user:
            return False
        sub = None
        if id_token_hint:
            try:
                payload = self._decode_id_token(request.client, id_token_hint)
            except jwt.PyJWTError:
                return False
            sub = payload.get("sub")
            session_sub = get_adapter().get_user_sub(
                request.client, context.request.user
            )
            if sub != session_sub:
                return False
        if claims:
            sub = claims.get("sub")
            session_sub = get_adapter().get_user_sub(
                request.client, context.request.user
            )
            if sub != session_sub:
                return False
        return True

    def get_authorization_code_scopes(
        self, client_id, code, redirect_uri, request
    ) -> List[str]:
        authorization_code = authorization_codes.lookup(client_id, code)
        if not authorization_code:
            return []
        return authorization_code["scopes"]

    def get_authorization_code_nonce(self, client_id, code, redirect_uri, request):
        authorization_code = authorization_codes.lookup(client_id, code)
        return authorization_code["code"].get("nonce")

    def finalize_id_token(self, id_token: dict, token: dict, token_handler, request):
        """
        https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        """
        adapter = get_adapter()
        id_token["sub"] = adapter.get_user_sub(request.client, request.user)
        id_token["iss"] = adapter.get_issuer()
        id_token["exp"] = id_token["iat"] + app_settings.ID_TOKEN_EXP
        id_token["jti"] = uuid.uuid4().hex
        if "email" in request.scopes:
            address = EmailAddress.objects.get_primary(request.user)
            if address:
                id_token.update(
                    {
                        "email": address.email,
                        "email_verified": address.verified,
                    }
                )
        if "profile" in request.scopes:
            full_name = request.user.get_full_name()
            last_name = getattr(request.user, "last_name", None)
            first_name = getattr(request.user, "first_name", None)
            username = user_username(request.user)
            profile_claims = {
                "name": full_name,
                "given_name": first_name,
                "family_name": last_name,
                "preferred_username": username,
            }
            for claim_key, claim_value in profile_claims.items():
                if claim_value:
                    id_token[claim_key] = claim_value
        get_adapter().populate_id_token(id_token, request.client, request.scopes)
        jwk_dict, private_key = jwkkit.load_jwk_from_pem(app_settings.PRIVATE_KEYS[0])
        return jwt.encode(
            id_token, private_key, algorithm="RS256", headers={"kid": jwk_dict["kid"]}
        )

    def validate_bearer_token(self, token, scopes, request) -> bool:
        instance = Token.objects.lookup(Token.Type.ACCESS_TOKEN, token)
        if not instance:
            return False
        request.user = instance.user
        return True

    def get_userinfo_claims(self, request):
        # FIXME
        claims = {"sub": get_adapter().get_user_sub(request.client, request.user)}
        return claims

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        uris = request.client.get_redirect_uris()
        if uris:
            return uris[0]
        return None

    def _decode_id_token(self, client, id_token: str):
        jwk_dict, private_key = jwkkit.load_jwk_from_pem(app_settings.PRIVATE_KEYS[0])
        return jwt.decode(
            id_token,
            audience=client.id,
            key=private_key.public_key(),
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_exp": True,
            },
        )
