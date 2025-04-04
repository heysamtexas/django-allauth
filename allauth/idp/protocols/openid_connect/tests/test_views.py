from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from django.urls import reverse
from django.utils.http import urlencode

from pytest_django.asserts import assertTemplateUsed


def test_cancel_authorization(auth_client, oidc_client):
    uri = oidc_client.get_redirect_uris()[0]
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode({"client_id": oidc_client.id, "response_type": "code"})
    )
    assert resp.status_code == HTTPStatus.OK
    assertTemplateUsed(resp, "idp/openid_connect/authorize_form.html")
    resp = auth_client.post(
        reverse("idp:openid_connect:authorize"),
        {
            "request": resp.context["form"]["request"].value(),
        },
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == f"{uri}?error=access_denied"


def test_authorization_code_flow(auth_client, oidc_client, enable_cache):
    uri = oidc_client.get_redirect_uris()[0]
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "response_type": "code",
                "scope": "openid profile email",
            }
        )
    )
    assert resp.status_code == HTTPStatus.OK
    assertTemplateUsed(resp, "idp/openid_connect/authorize_form.html")
    resp = auth_client.post(
        reverse("idp:openid_connect:authorize"),
        {
            "scopes": ["openid", "profile", "email"],
            "action": "grant",
            "request": resp.context["form"]["request"].value(),
        },
    )
    assert resp.status_code == HTTPStatus.FOUND
    redirected_uri = resp["location"]
    assert redirected_uri.startswith(uri)
    parts = urlparse(redirected_uri)
    params = parse_qs(parts.query)
    code = params["code"][0]
    resp = auth_client.post(
        reverse("idp:openid_connect:token"),
        {
            "code": code,
            "grant_type": "authorization_code",
            "client_id": oidc_client.id,
            "client_secret": "FIXME",
        },
    )
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert set(data.keys()) == {
        "access_token",
        "expires_in",
        "token_type",
        "scope",
        "refresh_token",
        "id_token",
    }
