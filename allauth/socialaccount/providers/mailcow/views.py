import contextlib
import requests

from allauth.socialaccount import app_settings
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
from allauth.utils import get_request_param


class MailcowAdapter(OAuth2Adapter):
    provider_id = "mailcow"
    settings = app_settings.PROVIDERS.get(provider_id, {})
    server = settings.get("SERVER", "https://hosted.mailcow.de")
    insecure_transport = settings.get("INSECURE_TRANSPORT", False)
    access_token_url = "{0}/oauth/token".format(server)
    authorize_url = "{0}/oauth/authorize".format(server)
    profile_url = "{0}/oauth/profile".format(server)

    def get_access_token_data(self, request, app, client, pkce_code_verifier=None):
        with self._allow_insecure_transport():
            return super().get_access_token_data(
                request, app, client, pkce_code_verifier
            )

    def complete_login(self, request, app, token, **kwargs):
        code = get_request_param(request, "code")
        with self._allow_insecure_transport():
            extra_data = self.get_user_info(token.token, code)

        return self.get_provider().sociallogin_from_response(request, extra_data)

    def get_user_info(self, access_token, code):
        resp = (
            get_adapter()
            .get_requests_session()
            .get(self.profile_url, params={"access_token": access_token, "code": code})
        )
        resp.raise_for_status()
        return resp.json()

    @contextlib.contextmanager
    def _allow_insecure_transport(self):
        def insecure_merge_environment_settings(
            self, url, proxies, stream, verify, cert
        ):
            settings = original_merge_environment_settings_method(
                self, url, proxies, stream, verify, cert
            )
            settings["verify"] = False
            return settings

        original_merge_environment_settings_method = (
            requests.Session.merge_environment_settings
        )
        try:
            if self.insecure_transport:
                requests.Session.merge_environment_settings = (
                    insecure_merge_environment_settings
                )
            yield
        finally:
            if self.insecure_transport:
                requests.Session.merge_environment_settings = (
                    original_merge_environment_settings_method
                )


oauth2_login = OAuth2LoginView.adapter_view(MailcowAdapter)
oauth2_callback = OAuth2CallbackView.adapter_view(MailcowAdapter)
