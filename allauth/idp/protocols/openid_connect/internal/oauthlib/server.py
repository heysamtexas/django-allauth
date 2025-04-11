from oauthlib.openid import Server

from allauth.idp.protocols.openid_connect import app_settings
from allauth.idp.protocols.openid_connect.internal.oauthlib.request_validator import (
    MyRequestValidator,
)


validator = MyRequestValidator()
server = Server(validator, token_expires_in=app_settings.ACCESS_TOKEN_EXPIRES_IN)
