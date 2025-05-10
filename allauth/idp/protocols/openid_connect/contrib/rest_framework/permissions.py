from rest_framework.permissions import BasePermission

from allauth.idp.protocols.openid_connect.internal.scope import (
    is_scope_granted,
)
from allauth.idp.protocols.openid_connect.models import Token


class TokenPermission(BasePermission):
    scope = None

    def has_permission(self, request, view):
        access_token = request.auth
        if (
            not isinstance(access_token, Token)
            or access_token.type != Token.Type.ACCESS_TOKEN
        ):
            return False
        return is_scope_granted(self.scope, access_token, request.method)

    @classmethod
    def has_scope(cls, scope):
        class TokenHasScopePermission(cls):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.scope = scope

        return TokenHasScopePermission
