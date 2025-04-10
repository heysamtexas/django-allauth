class AppSettings:
    def __init__(self, prefix):
        self.prefix = prefix

    def _setting(self, name, dflt):
        from allauth.utils import get_setting

        return get_setting(self.prefix + name, dflt)

    @property
    def ADAPTER(self):
        return self._setting(
            "ADAPTER",
            "allauth.idp.protocols.openid_connect.adapter.DefaultOpenIDConnectAdapter",
        )

    @property
    def ID_TOKEN_EXP(self) -> int:
        return 5 * 60

    @property
    def PRIVATE_KEYS(self) -> list[str]:
        return self._setting("PRIVATE_KEYS", [])


_app_settings = AppSettings("IDP_OPENID_CONNECT_")


def __getattr__(name):
    # See https://peps.python.org/pep-0562/
    return getattr(_app_settings, name)
