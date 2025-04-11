from oauthlib.openid import RequestValidator, Server

from allauth.idp.protocols.openid_connect import app_settings
from allauth.idp.protocols.openid_connect.internal.oauthlib.request_validator import (
    OAuthLibRequestValidator,
)


class OAuthLibServer(Server):
    def __init__(self):
        super().__init__(
            request_validator=OAuthLibRequestValidator(),
            token_expires_in=app_settings.ACCESS_TOKEN_EXPIRES_IN,
        )


def get_server():
    return OAuthLibServer()
