from http import HTTPStatus

from django.urls import reverse

import pytest


@pytest.fixture(autouse=True)
def prbc_settings(settings_impacting_urls):
    with settings_impacting_urls(ACCOUNT_PASSWORD_RESET_BY_CODE_ENABLED=True):
        yield


def test_flow(user, client, mailoutbox, get_last_password_reset_code, password_factory):
    new_password = password_factory()
    assert not user.check_password(new_password)
    resp = client.post(reverse("account_reset_password"), {"email": user.email})
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_confirm_password_reset_code")
    resp = client.post(
        reverse("account_confirm_password_reset_code"),
        {"code": get_last_password_reset_code(client, mailoutbox)},
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_complete_password_reset")
    resp = client.post(
        reverse("account_complete_password_reset"),
        {"password1": new_password, "password2": new_password},
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_password_reset_completed")
    user.refresh_from_db()
    assert user.check_password(new_password)
