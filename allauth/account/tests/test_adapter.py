from django.http import HttpRequest, HttpResponseRedirect
from django.urls import reverse

import pytest

from allauth.account.adapter import DefaultAccountAdapter
from allauth.core.exceptions import ImmediateHttpResponse


class PreLoginRedirectAccountAdapter(DefaultAccountAdapter):
    def pre_login(self, *args, **kwargs):
        raise ImmediateHttpResponse(HttpResponseRedirect("/foo"))


def test_adapter_pre_login(settings, user, user_password, client):
    settings.ACCOUNT_ADAPTER = (
        "allauth.account.tests.test_adapter.PreLoginRedirectAccountAdapter"
    )
    resp = client.post(
        reverse("account_login"),
        {"login": user.username, "password": user_password},
    )
    assert resp.status_code == 302
    assert resp["location"] == "/foo"


@pytest.mark.parametrize(
    "meta, expected_ip",
    [
        ({"HTTP_X_FORWARDED_FOR": "192.168.0.1"}, "192.168.0.1"),
        ({"HTTP_X_FORWARDED_FOR": "192.168.0.1, 192.168.0.2"}, "192.168.0.1"),
        ({"REMOTE_ADDR": "192.168.0.3"}, "192.168.0.3"),
        ({"REMOTE_ADDR": "192.168.0.3:8080"}, "192.168.0.3"),
        ({}, None),
    ],
)
def test_get_client_ip(meta, expected_ip):
    request = HttpRequest()
    request.META = meta
    adapter = DefaultAccountAdapter()
    assert adapter.get_client_ip(request) == expected_ip
