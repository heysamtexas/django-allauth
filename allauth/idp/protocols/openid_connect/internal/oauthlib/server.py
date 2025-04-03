from oauthlib.openid import Server

from allauth.idp.protocols.openid_connect.internal.oauthlib.request_validator import (
    MyRequestValidator,
)


validator = MyRequestValidator()
server = Server(validator)
