from django.urls import reverse
from django.utils.http import urlencode

from allauth import app_settings
from allauth.account.models import EmailAddress
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.socialaccount.providers.openid_connect.views import (
    OpenIDConnectOAuth2Adapter,
)


class OpenIDConnectProviderAccount(ProviderAccount):
    pass


class OpenIDConnectProvider(OAuth2Provider):
    id = "openid_connect"
    name = "OpenID Connect"
    account_class = OpenIDConnectProviderAccount
    oauth2_adapter_class = OpenIDConnectOAuth2Adapter

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = self.app.name

    @property
    def server_url(self):
        url = self.app.settings["server_url"]
        return self.wk_server_url(url)

    def wk_server_url(self, url):
        well_known_uri = "/.well-known/openid-configuration"
        if "/.well-known/" not in url:
            url += well_known_uri
        return url

    def get_login_url(self, request, **kwargs):
        url = reverse(
            self.app.provider + "_login", kwargs={"provider_id": self.app.provider_id}
        )
        if kwargs:
            url = url + "?" + urlencode(kwargs)
        return url

    def get_callback_url(self):
        return reverse(
            self.app.provider + "_callback",
            kwargs={"provider_id": self.app.provider_id},
        )

    @property
    def token_auth_method(self):
        return self.app.settings.get("token_auth_method")

    def get_default_scope(self):
        return ["openid", "profile", "email"]

    def extract_uid(self, data):
        uid_field = "sub"
        uid_field_from_settings = self.app.settings.get("uid_field")

        if not uid_field_from_settings:
            settings = app_settings.PROVIDERS.get(self.app.provider, {})
            uid_field_from_settings = settings.get("UID_FIELD")

        if uid_field_from_settings:
            split = uid_field_from_settings.split(".")

            temp_data = data

            for key in split:
                key_value = temp_data.get(key)

                if key_value is None:
                    temp_data = None
                    break
                else:
                    temp_data = temp_data.get(key)

            if (
                temp_data is not None
                and isinstance(temp_data, str)
                and uid_field in temp_data
            ):
                uid_field = temp_data

        return str(data[uid_field])

    def extract_common_fields(self, data):
        return dict(
            email=data.get("email"),
            username=data.get("preferred_username"),
            name=data.get("name"),
            user_id=data.get("user_id"),
            picture=data.get("picture"),
            last_name=data.get("family_name"),
            first_name=data.get("given_name"),
        )

    def extract_email_addresses(self, data):
        addresses = []
        email = data.get("email")
        if email:
            addresses.append(
                EmailAddress(
                    email=email,
                    verified=data.get("email_verified", False),
                    primary=True,
                )
            )
        return addresses

    def get_oauth2_adapter(self, request):
        return self.oauth2_adapter_class(request, self.app.provider_id)


provider_classes = [OpenIDConnectProvider]
