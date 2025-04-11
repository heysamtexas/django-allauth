import secrets

from oauthlib.openid import Server

from allauth.idp.protocols.openid_connect import app_settings
from allauth.idp.protocols.openid_connect.internal.oauthlib.request_validator import (
    OAuthLibRequestValidator,
)


def generate_token(request) -> str:
    return secrets.token_hex(20)


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
