import uuid

from django.core.management.utils import get_random_secret_key
from django.utils.translation import gettext_lazy as _

from allauth.core.internal.adapter import BaseAdapter
from allauth.idp.protocols.openid_connect import app_settings
from allauth.utils import import_attribute


class DefaultOpenIDConnectAdapter(BaseAdapter):
    scope_display = {
        "openid": _("View your user ID"),
        "email": _("View your email address"),
        "profile": _("View your basic profile information"),
    }

    def encrypt(self, text: str) -> str:
        """Secrets such as the client secret are stored in the database.  This
        hook can be used to encrypt those so that they are not stored in the
        clear in the database.
        """
        return text

    def decrypt(self, encrypted_text: str) -> str:
        """Counter part of ``encrypt()``."""
        text = encrypted_text
        return text

    def generate_client_id(self) -> str:
        """
        The client ID to use for newly created clients.
        """
        return uuid.uuid4().hex

    def generate_client_secret(self) -> str:
        """
        The client secret to use for newly created clients.
        """
        return get_random_secret_key()


def get_adapter() -> DefaultOpenIDConnectAdapter:
    return import_attribute(app_settings.ADAPTER)()
