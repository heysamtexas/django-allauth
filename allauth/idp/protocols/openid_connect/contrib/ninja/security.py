from django.http import HttpRequest

from ninja.security.base import AuthBase

from allauth.idp.protocols.openid_connect.internal.oauthlib.server import (
    get_server,
)
from allauth.idp.protocols.openid_connect.internal.oauthlib.utils import (
    extract_params,
)
from allauth.idp.protocols.openid_connect.internal.scope import (
    is_scope_granted,
)


class TokenAuth(AuthBase):
    openapi_type: str = "apiKey"
    scope = None

    def __init__(self, scope):
        super().__init__()
        self.scope = scope

    def __call__(self, request: HttpRequest):
        server = get_server()
        orequest = extract_params(request)
        valid, ctx = server.verify_request(*orequest, scopes=[])
        if not valid:
            return None
        if not is_scope_granted(self.scope, ctx.access_token, request.method):
            return None
        return ctx.access_token
