import requests

from django.urls import reverse
from django.utils.http import urlencode

from allauth.account.models import EmailAddress
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.internal import jwtkit
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
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
    supports_token_authentication = True

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

    def get_auth_params(self):
        """
        Expand the dictionary with additional optional parameters
        for OpenID Connect's authentication request.
        """
        ret = super().get_auth_params()

        # nonce is not handle here because it might have been configured in the parent.

        display = self.app.settings.get("authorization_parameters", {}).get("display")
        if display is not None:
            if not display:
                raise ValueError("OpenID Connect display value cannot be empty string.")

            if display not in ("page", "popup", "touch", "wap"):
                raise ValueError(f"Invalid OpenID Connect display value: {display}")

            ret["display"] = display

        prompt = self.app.settings.get("authorization_parameters", {}).get("prompt")
        if prompt is not None:
            if not prompt:
                raise ValueError("OpenID Connect prompt value cannot be empty string.")

            for prompt_token in prompt.split():
                if prompt_token not in ("none", "login", "consent", "select_account"):
                    raise ValueError(
                        f"Invalid OpenID Connect prompt value: {prompt_token}"
                    )

            ret["prompt"] = prompt

        max_age = self.app.settings.get("authorization_parameters", {}).get("max_age")
        if max_age is not None:
            if max_age < 0:
                raise ValueError("OpenID Connect max_age cannot be negative.")

            ret["max_age"] = max_age

        ui_locales = self.app.settings.get("authorization_parameters", {}).get(
            "ui_locales"
        )
        if ui_locales is not None:
            raise ValueError("OpenID Connect ui_locales is not implemented.")

        id_token_hint = self.app.settings.get("authorization_parameters", {}).get(
            "id_token_hint"
        )
        if id_token_hint is not None:
            raise ValueError("OpenID Connect id_token_hint is not implemented.")

        login_hint = self.app.settings.get("authorization_parameters", {}).get(
            "login_hint"
        )
        if login_hint is not None:
            raise ValueError("OpenID Connect login_hint is not implemented.")

        acr_values = self.app.settings.get("authorization_parameters", {}).get(
            "acr_values"
        )
        if acr_values is not None:
            raise ValueError("OpenID Connect acr_values is not implemented.")

        return ret

    @property
    def token_auth_method(self):
        return self.app.settings.get("token_auth_method")

    def get_default_scope(self):
        return ["openid", "profile", "email"]

    def extract_uid(self, data):
        return str(data["sub"])

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

    def verify_token(self, request, token):
        id_token = token.get("id_token")
        if not id_token:
            raise get_adapter().validation_error("invalid_token")
        try:
            oauth2_adapter = self.get_oauth2_adapter(request)
            openid_config = oauth2_adapter.openid_config
            identity_data = jwtkit.verify_and_decode(
                credential=id_token,
                keys_url=openid_config["jwks_uri"],
                issuer=openid_config["issuer"],
                audience=[self.app.client_id],
                lookup_kid=jwtkit.lookup_kid_jwk,
            )
        except (OAuth2Error, requests.RequestException) as e:
            raise get_adapter().validation_error("invalid_token") from e
        login = self.sociallogin_from_response(request, identity_data)
        return login


provider_classes = [OpenIDConnectProvider]
