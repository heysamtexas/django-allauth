import time
from types import SimpleNamespace

import pytest

from allauth.core.context import request_context
from allauth.idp.protocols.openid_connect.internal.oauthlib.request_validator import (
    MyRequestValidator,
)
from allauth.idp.protocols.openid_connect.models import Client


@pytest.fixture
def oidc_client():
    client = Client.objects.create()
    client.set_redirect_uris(["https://client/callback"])
    client.set_scopes(["profile", "openid", "email"])
    client.set_grant_types(["authorization_code"])
    client.set_response_types(["code"])
    client.save()
    return client


@pytest.fixture
def id_token_generator(rf):
    def f(client, user):
        with request_context(rf.get("/")):
            request = SimpleNamespace(client=client, user=user, scopes=["openid"])
            return MyRequestValidator().finalize_id_token(
                {
                    "aud": client.id,
                    "iat": int(time.time()),
                },
                {},
                None,
                request,
            )

    return f
