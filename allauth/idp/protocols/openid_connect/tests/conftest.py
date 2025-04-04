import pytest

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
