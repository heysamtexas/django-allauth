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


def get_adapter() -> DefaultOpenIDConnectAdapter:
    return import_attribute(app_settings.ADAPTER)()
