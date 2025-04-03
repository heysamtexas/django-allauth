import uuid
from typing import List

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


def generate_client_id() -> str:
    return uuid.uuid4().hex


class Client(models.Model):
    class GrantType(models.TextChoices):
        AUTHORIZATION_CODE = "authorization_code", _("Authorization code")
        CLIENT_CREDENTIALS = "client_credentials", _("Client credentials")
        REFRESH_TOKEN = "refresh_token", _("Refresh token")

    id = models.CharField(
        primary_key=True,
        max_length=100,
        default=generate_client_id,
    )
    name = models.CharField(
        max_length=100,
    )
    secret = models.CharField(max_length=200)
    scopes = models.TextField(
        help_text=_("The scope the client is allowed to request."),
    )
    grant_types = models.TextField(
        default=GrantType.AUTHORIZATION_CODE,
        help_text=_("A list of allowed grant types."),
    )
    redirect_uris = models.TextField()
    response_types = models.TextField(
        default="code",
        help_text=_("A list of allowed response types."),
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, blank=True, null=True, on_delete=models.CASCADE
    )
    skip_consent = models.BooleanField(
        default=False, help_text="Flag to allow skip the consent screen for this client"
    )
    created_at = models.DateTimeField(default=timezone.now)
    data = models.JSONField(blank=True, null=True, default=None)

    class Meta:
        verbose_name = _("client")
        verbose_name_plural = _("clients")

    def get_redirect_uris(self) -> List[str]:
        return self.redirect_uris.split()

    def set_redirect_uris(self, uris: List[str]):
        if isinstance(uris, str):
            raise ValueError(uris)
        self.redirect_uris = "\n".join(uris)

    def get_scopes(self) -> List[str]:
        return self.scopes.split()

    def set_scopes(self, scopes: List[str]):
        if isinstance(scopes, str):
            raise ValueError(scopes)
        self.scopes = "\n".join(scopes)

    def get_response_types(self) -> List[str]:
        return self.response_types.split()

    def set_response_types(self, response_types: List[str]):
        if isinstance(response_types, str):
            raise ValueError(response_types)
        self.response_types = "\n".join(response_types)

    def get_grant_types(self) -> List[str]:
        return self.grant_types.split()

    def set_grant_types(self, grant_types: List[str]):
        if isinstance(grant_types, str):
            raise ValueError(grant_types)
        self.grant_types = "\n".join(grant_types)

    def __str__(self) -> str:
        return self.id


class Token(models.Model):
    class Type(models.TextChoices):
        ACCESS_TOKEN = "at", "Access token"
        REFRESH_TOKEN = "rt", "Refresh token"
        AUTHORIZATION_CODE = "ac", "Authorization code"

    type = models.CharField(max_length=2, choices=Type.choices)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    data = models.JSONField(blank=True, null=True, default=None)
    created_at = models.DateTimeField(default=timezone.now())
    expires_at = models.DateTimeField(blank=True, null=True)
    value = models.CharField(primary_key=True, max_length=255)
    scopes = models.TextField(default="")

    # FIXME: indices
    # FIXME: composite primary key type, value?
    # FIXME: encrypt tokens?

    def __str__(self) -> str:
        return f"{self.get_type_display()} for user #{self.user_id}"
