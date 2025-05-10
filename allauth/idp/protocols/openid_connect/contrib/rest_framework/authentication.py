from rest_framework.authentication import BaseAuthentication

from allauth.idp.protocols.openid_connect.internal.oauthlib.server import (
    get_server,
)
from allauth.idp.protocols.openid_connect.internal.oauthlib.utils import (
    extract_params,
)


class TokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        server = get_server()
        orequest = extract_params(request)
        valid, ctx = server.verify_request(*orequest, scopes=[])
        if not valid:
            return None
        return ctx.user, ctx.access_token
