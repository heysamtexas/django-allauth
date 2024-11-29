from allauth.socialaccount.providers.oauth.urls import default_urlpatterns
from .provider import UberProvider

urlpatterns = default_urlpatterns(UberProvider)
