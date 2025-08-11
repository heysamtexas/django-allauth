from allauth.account.models import EmailAddress
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.socialaccount.providers.zitadel.views import ZitadelOAuth2Adapter


class ZitadelAccount(ProviderAccount):
    pass


class ZitadelProvider(OAuth2Provider):
    id = "zitadel"
    name = "Zitadel"
    account_class = ZitadelAccount
    oauth2_adapter_class = ZitadelOAuth2Adapter

    def get_default_scope(self):
        return ["openid", "profile", "email", "offline_access"]

    def extract_uid(self, data):
        return str(data["sub"])

    def extract_extra_data(self, data):
        return data

    def extract_email_addresses(self, data):
        return [
            EmailAddress(
                email=data["email"],
                verified=bool(data.get("email_verified", False)),
                primary=True
            )
        ]

    def extract_common_fields(self, data):
        ret = dict(
            email=data.get("email"),
            last_name=data.get("family_name"),
            first_name=data.get("given_name"),
        )
        preferred_username = data.get("preferred_username")
        if preferred_username:
            ret["username"] = preferred_username.partition("@")[0]
        return ret


provider_classes = [ZitadelProvider]
