from django.urls import include, path

from allauth.idp.protocols.openid_connect import views


app_name = "openid_connect"
urlpatterns = [
    path(
        ".well-known/openid-configuration",
        views.configuration,
        name="configuration",
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
