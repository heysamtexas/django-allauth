import time
import uuid
from types import SimpleNamespace

import pytest

from allauth.core.context import request_context
from allauth.idp.protocols.openid_connect.adapter import get_adapter
from allauth.idp.protocols.openid_connect.internal.oauthlib.request_validator import (
    OAuthLibRequestValidator,
)
from allauth.idp.protocols.openid_connect.models import Client, Token


@pytest.fixture
def oidc_client(db):
    client = Client.objects.create()
    client.set_redirect_uris(["https://client/callback"])
    client.set_scopes(["profile", "openid", "email"])
    client.set_grant_types(["authorization_code", "client_credentials", "password"])
    client.set_response_types(["code", "token"])
    client.save()
    return client


@pytest.fixture
def id_token_generator(rf):
    def f(client, user):
        with request_context(rf.get("/")):
            request = SimpleNamespace(client=client, user=user, scopes=["openid"])
            return OAuthLibRequestValidator().finalize_id_token(
                {
                    "aud": client.id,
                    "iat": int(time.time()),
                },
                {},
                None,
                request,
            )

    return f


@pytest.fixture
def access_token_generator():
    def f(client, user, scopes=["openid"]):
        token = uuid.uuid4().hex
        token_hash = get_adapter().hash_token(token)
        instance = Token(
            type=Token.Type.ACCESS_TOKEN,
            user=user,
            client=client,
            hash=token_hash,
        )
        instance.set_scopes(scopes)
        instance.save()
        return token, instance

    return f
