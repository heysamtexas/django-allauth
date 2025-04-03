from django.contrib.auth import get_user_model
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

from allauth.core.internal.httpkit import add_query_params
from allauth.idp.protocols.openid_connect.forms import AuthorizeForm
from allauth.idp.protocols.openid_connect.internal.oauthlib.server import (
    server,
)
from allauth.idp.protocols.openid_connect.internal.oauthlib.utils import (
    extract_params,
    response_from_error,
    response_from_return,
)
from allauth.idp.protocols.openid_connect.models import Client
from allauth.utils import build_absolute_uri


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
        }
        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response


configuration = ConfigurationView.as_view()


@method_decorator(login_required, name="dispatch")
class AuthorizeView(FormView):
    form_class = AuthorizeForm
    template_name = "idp/openid_connect/authorize_form.html"

    def dispatch(self, request, *args, **kwargs):
        if request.method == "GET":
            uri, http_method, body, headers = extract_params(self.request)

            try:
                self._scopes, self._request_info = (
                    server.validate_authorization_request(
                        uri, http_method, body, headers
                    )
                )
            # Errors that should be shown to the user on the provider website
            except errors.FatalClientError as e:
                return response_from_error(e)
            except errors.OAuth2Error as e:
                return HttpResponseRedirect(e.in_uri(e.redirect_uri))
            # FIXME: skip consent?
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
                return self.respond_with_access_denied()
        return super().dispatch(request, *args, **kwargs)

    def respond_with_access_denied(self):
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
        uri, http_method, body, headers = extract_params(self.request)
        scopes = form.cleaned_data["scopes"]
        credentials = {"user": self.request.user}
        credentials.update(self._request_info)
        try:
            headers, body, status = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials
            )
            return response_from_return(headers, body, status)

        except errors.FatalClientError as e:
            return response_from_error(e)

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
        uri, http_method, body, headers = extract_params(request)
        credentials = {}
        headers, body, status = server.create_token_response(
            uri, http_method, body, headers, credentials
        )

        return response_from_return(headers, body, status)


token = TokenView.as_view()


class UserInfoView(View):

    def get(self, request):
        uri, http_method, body, headers = extract_params(request)
        headers, body, status = server.create_userinfo_response(
            uri, http_method, body, headers
        )
        return response_from_return(headers, body, status)


user_info = UserInfoView.as_view()
