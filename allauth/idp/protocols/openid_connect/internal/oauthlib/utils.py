from typing import Tuple
from urllib.parse import urlparse, urlunparse

from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest

from oauthlib.common import quote, urlencode, urlencoded


def get_uri(request: HttpRequest):
    """
    Django considers "safe" some characters that aren't so for oauthlib.
    We have to search for them and properly escape.
    """
    parsed = list(urlparse(request.get_full_path()))
    unsafe = set(c for c in parsed[4]).difference(urlencoded)
    for c in unsafe:
        parsed[4] = parsed[4].replace(c, quote(c, safe=b""))

    return urlunparse(parsed)


def extract_params(request: HttpRequest) -> Tuple[str, str, str, dict]:
    uri = get_uri(request)
    body = urlencode(request.POST.items())
    headers = extract_headers(request)
    return uri, request.method, body, headers


def extract_headers(request):
    """
    You need to define extract_params and make sure it does not include file
    like objects waiting for input. In Django this is request.META['wsgi.input']
    and request.META['wsgi.errors']
    """
    headers = request.META.copy()
    headers.pop("wsgi.input", None)
    headers.pop("wsgi.errors", None)
    if "HTTP_AUTHORIZATION" in headers:
        headers["Authorization"] = headers["HTTP_AUTHORIZATION"]
    if "HTTP_ORIGIN" in headers:
        headers["Origin"] = headers["HTTP_ORIGIN"]
    return headers


def response_from_return(headers, body, status):
    response = HttpResponse(content=body, status=status)
    for k, v in headers.items():
        response[k] = v
    return response


def response_from_error(e):
    # FIXME: evil?
    return HttpResponseBadRequest(
        "Evil client is unable to send a proper request. Error is: " + e.description
    )
