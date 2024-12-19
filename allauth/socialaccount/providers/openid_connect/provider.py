from typing import Optional

from django.urls import reverse
from django.utils.http import urlencode
from django.utils.translation import get_language

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

    def get_logout_url(self, request, original_url: str) -> Optional[str]:
        """
        Returns a logout URL if an RP-initiated logout needs to be done.

        Returns None if no logout is possible (not configured,
        not logged in with this provider, id_token not stashed, etc).

        This is meant to be called by the account adapter's
        `get_logout_redirect_url` method.
        """

        adapter = self.get_oauth2_adapter(request)

        logout_url = adapter.end_session_endpoint or self.app.settings.get(
            "end_session_endpoint"
        )

        # if a logout URL was discovered from the provider or from settings
        if logout_url:
            # we could be called without the user being authed,
            # in this case do nothing
            if request.user.is_authenticated:
                # if the logout_data was stashed by us previously
                if id_token := request.session.pop("_allauth_logout_data"):

                    # use it to build a URI as per https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout  # noqa: E501
                    params = {
                        "id_token_hint": id_token,
                        "post_logout_redirect_uri": request.build_absolute_uri(
                            original_url
                        ),
                        "client_id": self.app.client_id,
                        "ui_locales": get_language(),
                    }

                    return logout_url + "?" + urlencode(params)

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


provider_classes = [OpenIDConnectProvider]
