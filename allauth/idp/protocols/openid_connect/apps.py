from django.apps import AppConfig

from allauth import app_settings


class OpenIDConnectConfig(AppConfig):
    name = "allauth.idp.protocols.openid_connect"
    label = "allauth_idp_oidc"
    default_auto_field = (
        app_settings.DEFAULT_AUTO_FIELD or "django.db.models.BigAutoField"
    )
