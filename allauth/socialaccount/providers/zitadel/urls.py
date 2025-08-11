from allauth.socialaccount.providers.oauth2.urls import default_urlpatterns
from allauth.socialaccount.providers.zitadel.provider import ZitadelProvider


urlpatterns = default_urlpatterns(ZitadelProvider)
