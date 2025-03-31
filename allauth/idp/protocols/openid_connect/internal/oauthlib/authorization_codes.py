from typing import Optional

from django.contrib.auth import get_user_model
from django.core.cache import cache

from allauth.account.internal.userkit import str_to_user_id, user_id_to_str


def cache_key(client_id: str, code: str):
    return f"allauth.idp.oidc.authorization_code[{client_id}:{code}]"


def create(client_id: str, code: dict, request):
    authorization_code = {
        "code": code,
        "client_id": request.client_id,
        "redirect_uri": request.redirect_uri,
        "user": user_id_to_str(request.user),
        "scopes": request.scopes,
        "claims": request.claims,
    }
    code_challenge = getattr(request, "code_challenge", None)
    if code_challenge:
        authorization_code["pkce"] = {
            "code_challenge": code_challenge,
            "code_challenge_method": request.code_challenge_method,
        }
    import pprint

    pprint.pprint(authorization_code)
    # FIXME: timeout setting
    # FIXME: cache? configurable?
    cache.set(
        cache_key(client_id, code["code"]),
        authorization_code,
        timeout=60,
    )


def lookup(client_id: str, code: str) -> Optional[dict]:
    return cache.get(cache_key(client_id, code))


def invalidate(client_id: str, code: str) -> None:
    cache.delete(cache_key(client_id, code))


def validate(client_id: str, code: str, request):
    authorization_code = lookup(client_id, code)
    if not authorization_code:
        return False
    user = (
        get_user_model()
        .objects.filter(pk=str_to_user_id(authorization_code["user"]))
        .first()
    )
    if not user:
        return False
    request.scopes = authorization_code["scopes"]
    request.user = user
    pkce = authorization_code.get("pkce")
    if pkce:
        request.code_challenge = pkce["code_challenge"]
        request.code_challenge_method = pkce["code_challenge_method"]
    request.claims = authorization_code["claims"]
    return True
