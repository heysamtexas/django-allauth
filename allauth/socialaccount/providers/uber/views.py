import requests
from allauth.socialaccount.providers.oauth.views import (
    OAuthAdapter,
    OAuthCallbackView,
    OAuthLoginView,
)


class UberOAuthAdapter(OAuthAdapter):
    provider_id = "uber"
    access_token_url = "https://login.uber.com/oauth/v2/token"
    authorize_url = "https://login.uber.com/oauth/v2/authorize"
    profile_url = "https://api.uber.com/v1/me"

    def complete_login(self, request, app, token, **kwargs):
        if not token or not token.token:
            raise ValueError("Invalid token for Uber OAuth2 login.")

        headers = {"Authorization": f"Bearer {token.token}"}
        try:
            response = requests.get(self.profile_url, headers=headers, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            raise ValueError(f"Failed to fetch Uber profile: {e}")

        extra_data = response.json()
        return self.get_provider().sociallogin_from_response(request, extra_data)


oauth_login = OAuthLoginView.adapter_view(UberOAuthAdapter)
oauth_callback = OAuthCallbackView.adapter_view(UberOAuthAdapter)
