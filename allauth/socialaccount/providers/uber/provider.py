from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth.provider import OAuthProvider


class UberAccount(ProviderAccount):
    def to_str(self):
        """Defines how the account appears in admin/UI."""
        return self.account.extra_data.get("first_name", self.account.uid)


class UberProvider(OAuthProvider):
    id = "uber"
    name = "Uber"
    account_class = UberAccount

    def extract_uid(self, data):
        # Uber uses "uuid" as the unique user identifier
        return str(data["uuid"])

    def extract_common_fields(self, data):
        # Map Uber's API fields to Django's user model
        return {
            "email": data.get("email"),
            "first_name": data.get("first_name"),
            "last_name": data.get("last_name"),
        }


provider_classes = [UberProvider]
