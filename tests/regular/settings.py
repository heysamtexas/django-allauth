from pathlib import Path

from django.contrib.auth.hashers import PBKDF2PasswordHasher

from tests.common.settings import INSTALLED_SOCIALACCOUNT_APPS


SECRET_KEY = "psst"
SITE_ID = 1
ALLOWED_HOSTS = (
    "testserver",
    "example.com",
)
USE_I18N = False
USE_TZ = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        "USER": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": "",
    }
}

ROOT_URLCONF = "tests.regular.urls"
LOGIN_URL = "/accounts/login/"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [Path(__file__).parent / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.dummy.DummyCache",
    }
}

MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
)

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    "django.contrib.humanize",
    "allauth",
    "allauth.account",
    "allauth.mfa",
    "allauth.usersessions",
    "allauth.headless",
    "allauth.idp.protocols.openid_connect",
) + INSTALLED_SOCIALACCOUNT_APPS

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
)

STATIC_ROOT = "/tmp/"  # Dummy
STATIC_URL = "/static/"


class MyPBKDF2PasswordHasher(PBKDF2PasswordHasher):
    """
    A subclass of PBKDF2PasswordHasher that uses 1 iteration.

    This is for test purposes only. Never use anywhere else.
    """

    iterations = 1


PASSWORD_HASHERS = [
    "tests.regular.settings.MyPBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]


ACCOUNT_ADAPTER = "tests.common.adapters.AccountAdapter"

SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_PROVIDERS = {
    "openid_connect": {
        "APPS": [
            {
                "provider_id": "unittest-server",
                "name": "Unittest Server",
                "client_id": "Unittest client_id",
                "client_secret": "Unittest client_secret",
                "settings": {
                    "server_url": "https://unittest.example.com",
                },
            },
            {
                "provider_id": "other-server",
                "name": "Other Example Server",
                "client_id": "other client_id",
                "client_secret": "other client_secret",
                "settings": {
                    "server_url": "https://other.example.com",
                },
            },
        ],
    }
}

ACCOUNT_LOGIN_BY_CODE_ENABLED = True

MFA_SUPPORTED_TYPES = ["totp", "webauthn", "recovery_codes"]
MFA_PASSKEY_LOGIN_ENABLED = True
MFA_PASSKEY_SIGNUP_ENABLED = True

HEADLESS_SERVE_SPECIFICATION = True

IDP_OPENID_CONNECT_PRIVATE_KEY = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAvGhvhFJkUwEa
jq48SQ2rWHxPC/kbG9lJb0cl6qjaLA27atC/aCdmnlMnnng7PrjfOLtPatXjuKk3
S8wpIqB74wuzEnBs+/3BaqylxN1pkazRv+w0i26B7igLQVjsUXkz/icSPoSkZSxO
MB4vbGfwnbyUOqHaWumnDwXOZ4FKrxxXMSJcJVF141MaqANh90Wwsx7PK/Nb8hkj
blKcbfSn9x5Q7jRN2e1yfC6xtsrR+q5o26m0H2uXiFaWtxH6GPKnsgA90RmIblQ7
nYmg39C01Xli0z5ehzd5oAGpXEDP9uO9+1kVWor8TETl7vpaVqnauLx/tTl09qEM
WpX6VmFVAgMBAAECggEAEdPbnSUSMfFzkq9L8ouXVhgTN4SWACntSVufqyQvhi64
/nL86BeMPXO7oViJKoG8u/kVal0pd6znChRayBtJ2OvBc0jrWUldyXxCh/rTuCYf
ZC9qe9nB2QbccV4UCZfnrCWAG7HotwQcuwa8ZAqU+q68eMGLoxTxs+Ax20u7q9qp
Y+QNNZOuH+1pC8l+0CaTTpFa1sty+/xnGtM6UgaLVQ7E4ZvFRWyWfIAzWFzFfFWW
oVK7mYD8uVPMEpHPPlaNj+0C7LNM1NUpg/ifKPYl13OnhQr2WMji35LwrEsK0lpr
tXw6wm7rl9NbXC93hpW9V252KNuL3LbN9lLAICSOAQKBgQD24BY4dCRErTZY8+Zp
fBf+2h6RPHtukTFsyMdC903R4ZuLGSoteKTesAte2CfsG5YvgXx/eZHGRvnPBF7A
Pjb/ZJnk3HzsHirivZ19xvd5MVQRobUXmh42gJW5V5XixqMjBfpoWcOL5H1ly9m+
2EZKeh7B8wNXTj/dCoOmNbF3QQKBgQDH3A8gkWT6udSMTVT1oxb1ifJUTWtwdfrn
rZQtk1ov962sXwMqglt9sdt9+9gajF7LzxLxStRUY16U0QUMjfHVQiQQfzfnI2a7
r2dg1g03msDg7QRVD/NHuzkQL37zeQQalrqTCbq43/CFbJDlGkr9xqNfAICya4Vp
gJW2zdJZFQKBgQCcS4Rl20m23P5iVI+USscaRtdBVcxDVNK4r2hPwifXb4C9EIJ+
ZTnj7gpU0n574X80tkKupbWflQHEiVy/UuQYzoULunewOO0nvan+nj/Az3UM8Jao
yZ7FHKUtwQCYoO9ZVgiRlfrSDydAkk1ZoKznq+bbHVIJLPYLqANu7+FZwQKBgQCn
Oq35rU7WMGn137soMgfC+mMnQQSWPFHuSyKCpBpBqrfKVFH83siZOxoSp4kiZbPo
S2NpPRi/Z8o7MU5NO/RPYiF1IE3xfIC4qMMSlujGTxn22rvWRRtmOPU9YtCR/v99
FAQXhnuTt+W0bqwq1z5KbExE8NG++RLPvYUISd4pJQKBgGxyMWgE2AeILIcrw/Ts
zM1ct2vV7Iet8eVRPUAzESQu0aGBm7Eho9+mh3vUJtlStChJIvCT+lbEgXmsDGMk
HxD4lATnNILRfRTdPgu8IYS3/A4LoXjjhsPmx8NQ6PwnKnseFtQMBKQsX2HVfMVP
vOZ+KpqzUW/vig+SalRbQMIR
-----END PRIVATE KEY-----
"""
