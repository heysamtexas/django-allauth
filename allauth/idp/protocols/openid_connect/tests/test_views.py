from http import HTTPStatus
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

from django.urls import reverse
from django.utils.http import urlencode

import jwt
import pytest
from pytest_django.asserts import assertTemplateUsed

from allauth.idp.protocols.openid_connect.adapter import get_adapter
from allauth.idp.protocols.openid_connect.models import Token


def test_cancel_authorization(auth_client, oidc_client):
    redirect_uri = oidc_client.get_redirect_uris()[0]
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
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
    assert resp["location"] == f"{redirect_uri}?error=access_denied"


@pytest.mark.parametrize(
    "scopes",
    [
        ("openid", "profile", "email"),
        ("openid", "profile"),
        ("openid",),
    ],
)
def test_authorization_code_flow(auth_client, user, oidc_client, enable_cache, scopes):
    redirect_uri = oidc_client.get_redirect_uris()[0]
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "redirect_uri": redirect_uri,
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
    assert redirected_uri.startswith(redirected_uri)
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
            "redirect_uri": redirect_uri,
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
    redirect_uri = oidc_client.get_redirect_uris()[0]
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
                "redirect_uri": redirect_uri,
            }
        )
    )
    assert resp.status_code == HTTPStatus.FOUND
    redirected_uri = resp["location"]
    assert redirected_uri.startswith(redirect_uri)
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
            "redirect_uri": redirect_uri,
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
    redirect_uri = oidc_client.get_redirect_uris()[0]
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
                "redirect_uri": redirect_uri,
            }
        )
    )
    assert resp.status_code == HTTPStatus.OK


def test_authorize_id_token_hint_mismatch(
    user, id_token_generator, oidc_client, auth_client, user_factory
):
    redirect_uri = oidc_client.get_redirect_uris()[0]
    # Pass along ID token as hint
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "id_token_hint": id_token_generator(oidc_client, user_factory()),
                "response_type": "code",
                "redirect_uri": redirect_uri,
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


def test_userinfo_bad_token(client, oidc_client, user):
    # Pass along ID token as hint
    resp = client.get(reverse("idp:openid_connect:userinfo"))
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json() == {
        "error": "invalid_token",
        "error_description": "The access token provided is expired, revoked, malformed, or invalid for other reasons.",
    }


@pytest.mark.parametrize("scopes", [("openid",), ("openid", "email")])
def test_userinfo(client, oidc_client, user, access_token_generator, scopes):
    # Pass along ID token as hint
    token, _ = access_token_generator(oidc_client, user, scopes=scopes)
    resp = client.get(
        reverse("idp:openid_connect:userinfo"),
        HTTP_AUTHORIZATION=f"Bearer {token}",
    )
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert data["sub"] == get_adapter().get_user_sub(oidc_client, user)
    if "email" in scopes:
        assert data["email"] == user.email
        assert data["email_verified"] == True
    else:
        assert "email" not in data


def test_revoke(client, oidc_client, user, access_token_generator):
    token, instance = access_token_generator(oidc_client, user)
    _, instance_to_keep = access_token_generator(oidc_client, user)
    resp = client.post(
        reverse("idp:openid_connect:revoke"),
        data={
            "client_id": oidc_client.id,
            "client_secret": oidc_client.secret,
            "token": token,
        },
    )
    assert resp.status_code == 200
    assert not Token.objects.filter(pk=instance.pk).exists()
    assert Token.objects.filter(pk=instance_to_keep.pk).exists()


def test_client_credentials(client, oidc_client):
    resp = client.post(
        reverse("idp:openid_connect:token"),
        data={
            "client_id": oidc_client.id,
            "client_secret": oidc_client.secret,
            "scope": "profile email",
            "grant_type": "client_credentials",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "access_token": ANY,
        "expires_in": 3600,
        "scope": "profile email",
        "token_type": "Bearer",
    }
    token = Token.objects.lookup(Token.Type.ACCESS_TOKEN, data["access_token"])
    assert token.client == oidc_client
    assert token.get_scopes() == ["profile", "email"]


def test_password_grant_is_blocked(client, oidc_client, user, user_password):
    resp = client.post(
        reverse("idp:openid_connect:token"),
        data={
            "client_id": oidc_client.id,
            "client_secret": oidc_client.secret,
            # These are valid credentials.
            "username": user.username,
            "password": user_password,
            "scope": "profile email",
            "grant_type": "password",
        },
    )
    # We don't crash, but also don't grant.
    assert resp.status_code == 400
    assert resp.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid credentials given.",
    }


def test_implicit_grant_flow(auth_client, user, oidc_client, enable_cache):
    redirect_uri = oidc_client.get_redirect_uris()[0]
    scopes = ["openid", "profile"]
    resp = auth_client.get(
        reverse("idp:openid_connect:authorize")
        + "?"
        + urlencode(
            {
                "client_id": oidc_client.id,
                "response_type": "token",
                "scope": " ".join(scopes),
                "nonce": "some-nonce",
                "state": "some-state",
                "redirect_uri": redirect_uri,
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
    # "https://client/callback#access_token=baI5uc9m5JWc6afKqaZ9eymeOrq1hz&expires_in=3600&token_type=Bearer&scope=openid+profile&state=some-state"
    assert resp.status_code == HTTPStatus.FOUND
    parts = urlparse(resp["location"])
    data = parse_qs(parts.fragment)
    assert data == {
        "access_token": ANY,
        "expires_in": ["3600"],
        "scope": ["openid profile"],
        "token_type": ["Bearer"],
        "state": ["some-state"],
    }


def test_userinfo_access_token_as_query(
    client, oidc_client, user, access_token_generator
):
    # Pass along ID token as hint
    token, _ = access_token_generator(oidc_client, user, scopes=["openid"])
    resp = client.get(
        reverse("idp:openid_connect:userinfo")
        + "?"
        + urlencode({"access_token": token}),
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
