from django.contrib import admin

from allauth.idp.protocols.openid_connect.models import Client, Token


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    raw_id_fields = ("owner",)
    list_display = (
        "id",
        "owner",
        "skip_consent",
    )


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    raw_id_fields = ("client", "user")
    list_display = (
        "client",
        "type",
        "user",
        "created_at",
        "expires_at",
    )
    list_filter = ("type",)

    # FIXME: garble/hide values
