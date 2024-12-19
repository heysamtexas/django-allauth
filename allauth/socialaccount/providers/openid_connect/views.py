from typing import Optional

from django.urls import reverse

from allauth.account.internal.decorators import login_not_required
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialToken
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
from allauth.utils import build_absolute_uri


class OpenIDConnectOAuth2Adapter(OAuth2Adapter):
    def __init__(self, request, provider_id):
        self.provider_id = provider_id
        super().__init__(request)

    @property
    def openid_config(self):
        if not hasattr(self, "_openid_config"):
            server_url = self.get_provider().server_url
            resp = get_adapter().get_requests_session().get(server_url)
            resp.raise_for_status()
            self._openid_config = resp.json()
        return self._openid_config

    @property
    def basic_auth(self):
        token_auth_method = self.get_provider().app.settings.get("token_auth_method")
        if token_auth_method:
            return token_auth_method == "client_secret_basic"  # nosec
        return "client_secret_basic" in self.openid_config.get(
            "token_endpoint_auth_methods_supported", []
        )

    @property
    def access_token_url(self):
        return self.openid_config["token_endpoint"]

    @property
    def authorize_url(self):
        return self.openid_config["authorization_endpoint"]

    @property
    def profile_url(self):
        return self.openid_config["userinfo_endpoint"]

    @property
    def end_session_endpoint(self) -> Optional[str]:
        """
        The "RP-initiated logout" endpoint, from the autodiscovered config.
        """
        return self.openid_config.get("end_session_endpoint")

    def parse_token(self, data: dict):
        """
        Capture and stash the `id_token` on the SocialToken for use elsewhere.

        The default account adapter will read this and move to the request's session
        later on during the login process. We can't easily do it in this class
        as we're not always told whether this is an actual *login* or merely
        connecting an additional social account to an existing user
        (we only want to do this on an actual *login*), thus we let the adapter do it.
        """
        token = super().parse_token(data)

        if "id_token" in data:
            token.logout_data = data["id_token"]

        return token

    def complete_login(self, request, app, token: SocialToken, **kwargs):
        response = (
            get_adapter()
            .get_requests_session()
            .get(self.profile_url, headers={"Authorization": "Bearer " + token.token})
        )
        response.raise_for_status()
        extra_data = response.json()
        return self.get_provider().sociallogin_from_response(request, extra_data)

    def get_callback_url(self, request, app):
        callback_url = reverse(
            "openid_connect_callback", kwargs={"provider_id": self.provider_id}
        )
        protocol = self.redirect_uri_protocol
        return build_absolute_uri(request, callback_url, protocol)


@login_not_required
def login(request, provider_id):
    view = OAuth2LoginView.adapter_view(
        OpenIDConnectOAuth2Adapter(request, provider_id)
    )
    return view(request)


@login_not_required
def callback(request, provider_id):
    view = OAuth2CallbackView.adapter_view(
        OpenIDConnectOAuth2Adapter(request, provider_id)
    )
    return view(request)
