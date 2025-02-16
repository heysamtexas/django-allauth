from typing import Optional

from django.http import HttpRequest

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.internal.flows import password_reset
from allauth.account.internal.flows.code_verification import (
    AbstractCodeVerificationProcess,
)
from allauth.account.internal.userkit import user_id_to_str


PASSWORD_RESET_VERIFICATION_SESSION_KEY = "account_password_reset_verification"


class PasswordResetVerificationProcess(AbstractCodeVerificationProcess):
    def __init__(self, request, state, user=None):
        self.request = request
        super().__init__(
            state=state,
            timeout=app_settings.PASSWORD_RESET_BY_CODE_TIMEOUT,
            max_attempts=app_settings.PASSWORD_RESET_BY_CODE_MAX_ATTEMPTS,
            user=None,
        )

    def abort(self):
        self.request.session.pop(PASSWORD_RESET_VERIFICATION_SESSION_KEY, None)

    def finish(self):
        self.request.session.pop(PASSWORD_RESET_VERIFICATION_SESSION_KEY, None)
        password_reset.finalize_password_reset(self.request, self.user)

    def persist(self):
        self.request.session[PASSWORD_RESET_VERIFICATION_SESSION_KEY] = self.state

    @classmethod
    def initial_state(cls, user, email):
        state = super().initial_state(user)
        state.update({"email": email})
        return state

    def send(self):
        adapter = get_adapter()
        code = adapter.generate_password_reset_code()
        self.state.update({"code": code, "user_id": user_id_to_str(self.user)})
        context = {
            "request": self.request,
            "code": self.code,
        }
        adapter.send_mail(
            "account/email/password_reset_code", self.state["email"], context
        )

    @classmethod
    def initiate(cls, *, request, user, email: str):
        state = cls.initial_state(user, email)
        process = PasswordResetVerificationProcess(request, state=state, user=user)
        process.send()
        process.persist()
        return process

    @classmethod
    def resume(
        cls, request: HttpRequest
    ) -> Optional["PasswordResetVerificationProcess"]:
        state = request.session.get(PASSWORD_RESET_VERIFICATION_SESSION_KEY)
        if not state:
            return None
        process = PasswordResetVerificationProcess(request, state=state)
        if not process.is_valid():
            return None
        return process
