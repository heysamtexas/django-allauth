from django.dispatch import Signal

from allauth.account import app_settings

from .models import UserSession

# Provides the arguments "session", "from_user_agent", "to_user_agent"
user_agent_changed = Signal()

# Provides the arguments "session", "from_ip", "to_ip"
ip_changed = Signal()


def on_user_logged_in(sender, **kwargs):
    request = kwargs["request"]
    UserSession.objects.create_from_request(request)


def on_password_changed(sender, **kwargs):
    if not app_settings.LOGOUT_ON_PASSWORD_CHANGE:
        request = kwargs["request"]
        UserSession.objects.create_from_request(request)
