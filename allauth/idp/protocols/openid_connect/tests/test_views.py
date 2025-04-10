from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from django.urls import reverse
from django.utils.http import urlencode

import jwt
import pytest
from pytest_django.asserts import assertTemplateUsed


def test_cancel_authorization(auth_client, oidc_client):
    uri = oidc_client.get_redirect_uris()[0]
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "response_type": "code",
            }
        )
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


@pytest.mark.parametrize(
    "scopes",
    [
        ("openid", "profile", "email"),
        ("openid", "profile"),
        ("openid",),
    ],
)
def test_authorization_code_flow(auth_client, user, oidc_client, enable_cache, scopes):
    uri = oidc_client.get_redirect_uris()[0]
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "response_type": "code",
                "scope": " ".join(scopes),
                "nonce": "some-nonce",
                "state": "some-state",
            }
        )
    )
    assert resp.status_code == HTTPStatus.OK
    assertTemplateUsed(resp, "idp/openid_connect/authorize_form.html")
    resp = auth_client.post(
        reverse("idp:openid_connect:authorize"),
        {
            "scopes": scopes,
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
            "client_secret": oidc_client.get_secret(),
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

    # ID token
    id_token = data["id_token"]
    decoded = jwt.decode(id_token, options={"verify_signature": False})
    assert decoded["sub"] == str(user.pk)
    assert decoded["nonce"] == "some-nonce"
    if "email" in scopes:
        assert decoded["email"] == user.email
    else:
        assert "email" not in decoded
    if "profile" in scopes:
        assert decoded["preferred_username"] == user.username
    else:
        assert "preferred_username" not in decoded


def test_authorization_code_flow_skip_consent(
    auth_client, user, oidc_client, enable_cache
):
    oidc_client.skip_consent = True
    oidc_client.save()
    uri = oidc_client.get_redirect_uris()[0]
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "response_type": "code",
                "scope": "openid profile email",
                "nonce": "some-nonce",
                "state": "some-state",
            }
        )
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
            "client_secret": oidc_client.get_secret(),
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


def test_authorize_id_token_hint_match(
    user, id_token_generator, oidc_client, auth_client, user_factory
):
    # Pass along ID token as hint
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "id_token_hint": id_token_generator(oidc_client, user),
                "response_type": "code",
                "scope": "openid",
                "nonce": "some-nonce",
                "state": "some-state",
            }
        )
    )
    assert resp.status_code == HTTPStatus.OK


def test_authorize_id_token_hint_mismatch(
    user, id_token_generator, oidc_client, auth_client, user_factory
):
    # Pass along ID token as hint
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "id_token_hint": id_token_generator(oidc_client, user_factory()),
                "response_type": "code",
                "scope": "openid",
                "nonce": "some-nonce",
                "state": "some-state",
            }
        )
    )
    assert resp.status_code == HTTPStatus.FOUND
    parts = urlparse(resp["location"])
    params = parse_qs(parts.query)
    assert params["error"] == ["login_required"]
    assert params["error_description"] == [
        "Session user does not match client supplied user."
    ]
