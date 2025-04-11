from django.urls import include, path

from allauth.idp.protocols.openid_connect import views


app_name = "openid_connect"
urlpatterns = [
    path(
        ".well-known/",
        include(
            [
                path(
                    "openid-configuration",
                    views.configuration,
                    name="configuration",
                ),
                path(
                    "jwks.json",
                    views.jwks,
                    name="jwks",
                ),
            ]
        ),
    ),
    path(
        "identity/",
        include(
            [
                path(
                    "oidc/",
                    include(
                        [
                            path(
                                "token",
                                views.token,
                                name="token",
                            ),
                            path(
                                "authorize",
                                views.authorize,
                                name="authorize",
                            ),
                            path(
                                "revoke",
                                views.revoke,
                                name="revoke",
                            ),
                            path(
                                "userinfo",
                                views.user_info,
                                name="userinfo",
                            ),
                        ]
                    ),
                )
            ]
        ),
    ),
]
