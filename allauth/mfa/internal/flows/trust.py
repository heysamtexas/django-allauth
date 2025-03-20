from django.http import HttpRequest, HttpResponse

from allauth.mfa import app_settings


def trust_browser(request: HttpRequest, response: HttpResponse) -> None:
    response.set_cookie(
        app_settings.TRUST_COOKIE_NAME, "yo", path=app_settings.TRUST_COOKIE_PATH
    )


def is_trusted_browser(request: HttpRequest) -> bool:
    value = request.COOKIES.get(app_settings.TRUST_COOKIE_NAME)
    return value == "yo"
