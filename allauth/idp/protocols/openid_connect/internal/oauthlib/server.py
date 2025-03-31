from oauthlib.oauth2 import Server

from allauth.idp.protocols.openid_connect.internal.oauthlib.request_validator import (
    MyRequestValidator,
)


# FIXME
client_id = "fixme"
validator = MyRequestValidator()
server = Server(validator)
