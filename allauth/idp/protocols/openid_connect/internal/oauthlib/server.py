import secrets

from oauthlib.openid import Server

from allauth.idp.protocols.openid_connect import app_settings
from allauth.idp.protocols.openid_connect.internal.oauthlib.request_validator import (
    OAuthLibRequestValidator,
)


def generate_token(request) -> str:
    # oauch.io -- at 20, we get:
    #    Out of 11 valid authorization responses, the
    #    average calculated entropy for the access tokens was 144,3 (±7,1) bits
    return secrets.token_urlsafe(25)


class OAuthLibServer(Server):
    def __init__(self):
        super().__init__(
            # 160 bit token is recommended, oauthlib uses less.
            token_generator=generate_token,
            request_validator=OAuthLibRequestValidator(),
            token_expires_in=app_settings.ACCESS_TOKEN_EXPIRES_IN,
        )


def get_server():
    return OAuthLibServer()
