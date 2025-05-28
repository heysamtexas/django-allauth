import requests

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.base import AuthAction, ProviderAccount
from allauth.socialaccount.providers.microsoft.views import (
    MicrosoftGraphOAuth2Adapter,
)
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider


class MicrosoftGraphAccount(ProviderAccount):
    def get_avatar_url(self):
        return self.account.extra_data.get("photo")


class MicrosoftGraphProvider(OAuth2Provider):
    id = "microsoft"
    name = "Microsoft"
    account_class = MicrosoftGraphAccount
    oauth2_adapter_class = MicrosoftGraphOAuth2Adapter
    supports_token_authentication = True

    def get_default_scope(self):
        """
        Docs on Scopes and Permissions:
        https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#scopes-and-permissions
        """
        return ["User.Read"]

    def get_auth_params_from_request(self, request, action):
        ret = super().get_auth_params_from_request(request, action)
        if action == AuthAction.REAUTHENTICATE:
            ret["prompt"] = "select_account"
        return ret

    def extract_uid(self, data):
        return str(data["id"])

    def extract_common_fields(self, data):
        return dict(
            email=data.get("mail") or data.get("userPrincipalName"),
            username=data.get("mailNickname"),
            last_name=data.get("surname"),
            first_name=data.get("givenName"),
        )

    def verify_token(self, request, token):
        try:
            adapter = self.get_oauth2_adapter(request)
            parsed_token = adapter.parse_token(token)
            login = adapter.complete_login(request, self.app, parsed_token)
            return login
        except (OAuth2Error, requests.RequestException) as e:
            raise get_adapter().validation_error("invalid_token") from e


provider_classes = [MicrosoftGraphProvider]
