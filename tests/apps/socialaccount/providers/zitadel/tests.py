from django.test import TestCase

from allauth.socialaccount.providers.zitadel.provider import ZitadelProvider
from tests.apps.socialaccount.base import OAuth2TestsMixin
from tests.mocking import MockedResponse


class ZitadelTests(OAuth2TestsMixin, TestCase):
    provider_id = ZitadelProvider.id

    def get_mocked_response(self):
        return MockedResponse(
            200,
            """
            {
                "sub": "123456789012345678",
                "name": "Jon Smith",
                "locale": "en",
                "email": "jsmith@example.com",
                "nickname": "Jon Smith",
                "preferred_username": "jsmith@example.com",
                "given_name": "Jon",
                "family_name": "Smith",
                "zoneinfo": "America/Los_Angeles",
                "updated_at": 1601285210,
                "email_verified": true
            }
        """,
        )

    def get_expected_to_str(self):
        return "jsmith@example.com"
