from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import PermissionDenied
from django.core.signing import BadSignature, Signer
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.edit import FormView

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.errors import OAuth2Error

from allauth.account import app_settings as account_settings
from allauth.account.internal.decorators import login_not_required
from allauth.core.internal import jwkkit
from allauth.core.internal.httpkit import add_query_params
from allauth.idp.protocols.openid_connect.adapter import get_adapter
from allauth.idp.protocols.openid_connect.forms import AuthorizeForm
from allauth.idp.protocols.openid_connect.internal.oauthlib.server import (
    server,
)
from allauth.idp.protocols.openid_connect.internal.oauthlib.utils import (
    convert_response,
    extract_params,
    respond_html_error,
    respond_json_error,
)
from allauth.idp.protocols.openid_connect.models import Client
from allauth.utils import build_absolute_uri


@method_decorator(login_not_required, name="dispatch")
class ConfigurationView(View):
    def get(self, request):
        data = {
            "authorization_endpoint": build_absolute_uri(
                request, reverse("idp:openid_connect:authorize")
            ),
            "token_endpoint": build_absolute_uri(
                request, reverse("idp:openid_connect:token")
            ),
            "userinfo_endpoint": build_absolute_uri(
                request, reverse("idp:openid_connect:userinfo")
            ),
            "jwks_uri": build_absolute_uri(request, reverse("idp:openid_connect:jwks")),
            "issuer": get_adapter().get_issuer(),
            "response_types_supported": [
                "code",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response


configuration = ConfigurationView.as_view()


@method_decorator(login_required, name="dispatch")
class AuthorizeView(FormView):
    form_class = AuthorizeForm
    template_name = (
        "idp/openid_connect/authorize_form." + account_settings.TEMPLATE_EXTENSION
    )

    def dispatch(self, request, *args, **kwargs):
        if request.method == "GET":
            orequest = extract_params(self.request)
            try:
                self._scopes, self._request_info = (
                    server.validate_authorization_request(*orequest)
                )
            # Errors that should be shown to the user on the provider website
            except errors.FatalClientError as e:
                return respond_html_error(request, e)
            except errors.OAuth2Error as e:
                return HttpResponseRedirect(e.in_uri(e.redirect_uri))
            if self._request_info["request"].client.skip_consent:
                return self._skip_consent()
        elif request.method == "POST":
            signed_request_info = request.POST.get("request")
            try:
                signer = Signer()
                self._scopes, self._request_info = signer.unsign_object(
                    signed_request_info
                )
            except BadSignature:
                raise PermissionDenied
            if request.POST.get("action") != "grant":
                return self._respond_with_access_denied()
        return super().dispatch(request, *args, **kwargs)

    def _skip_consent(self):
        scopes = self._request_info["request"].scopes
        form_kwargs = self.get_form_kwargs()
        form_kwargs["data"] = {
            "scopes": scopes,
            "request": "not-relevant-for-skip-consent",
        }
        form = self.form_class(**form_kwargs)
        if not form.is_valid():
            # Shouldn't occur.
            raise PermissionDenied()
        return self.form_valid(form)

    def _respond_with_access_denied(self):
        redirect_uri = self._request_info.get("redirect_uri")
        state = self._request_info.get("state")
        params = {"error": "access_denied"}
        if state:
            params["state"] = state
        return HttpResponseRedirect(add_query_params(redirect_uri, params))

    def get_form_kwargs(self):
        ret = super().get_form_kwargs()
        ret["requested_scopes"] = self._scopes
        return ret

    def get_initial(self):
        signer = Signer()
        ret = {}
        request_info = self._request_info
        request_info.pop("request", None)
        prompt = request_info.get("prompt")
        if isinstance(prompt, set):
            request_info["prompt"] = list(prompt)
        ret["request"] = signer.sign_object((self._scopes, request_info))
        return ret

    def form_valid(self, form):
        orequest = extract_params(self.request)
        scopes = form.cleaned_data["scopes"]
        credentials = {"user": self.request.user}
        credentials.update(self._request_info)
        try:
            oresponse = server.create_authorization_response(
                *orequest, scopes=scopes, credentials=credentials
            )
            return convert_response(*oresponse)

        except errors.FatalClientError as e:
            return respond_html_error(self.request, e)

    def get_context_data(self, **kwargs):
        ret = super().get_context_data(**kwargs)
        ret.update(
            {
                "client": Client.objects.get(id=self._request_info["client_id"]),
                "site": get_current_site(self.request),
            }
        )
        return ret


authorize = AuthorizeView.as_view()


@method_decorator(csrf_exempt, name="dispatch")
class TokenView(View):

    def post(self, request):
        orequest = extract_params(request)
        oresponse = server.create_token_response(*orequest)
        return convert_response(*oresponse)


token = TokenView.as_view()


class UserInfoView(View):

    def get(self, request):
        orequest = extract_params(request)
        try:
            oresponse = server.create_userinfo_response(*orequest)
            return convert_response(*oresponse)
        except OAuth2Error as e:
            return respond_json_error(request, e)


user_info = UserInfoView.as_view()


@method_decorator(login_not_required, name="dispatch")
class JwksView(View):
    def get(self, request, *args, **kwargs):
        keys = []
        for pem in settings.IDP_OPENID_CONNECT_PRIVATE_KEYS:
            jwk, _ = jwkkit.load_jwk_from_pem(pem)
            keys.append(jwk)
        response = JsonResponse({"keys": keys})
        response["Access-Control-Allow-Origin"] = "*"
        return response


jwks = JwksView.as_view()


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class RevokeView(View):
    def post(self, request, *args, **kwargs):
        orequest = extract_params(request)
        oresponse = server.create_revocation_response(*orequest)
        return convert_response(*oresponse)


revoke = RevokeView.as_view()
