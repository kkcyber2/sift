"""HTTP transport. The only file that touches the network.

Deliberately thin: it sends one GET with one query parameter and returns the body.
It refuses non-http(s) schemes and refuses to follow redirects off the original host,
so a scan cannot be bounced somewhere the operator did not authorise.
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from .scan import Response

USER_AGENT = "sift/1.0 (+https://github.com/kkcyber2/sift)"
TIMEOUT = 10
MAX_BODY = 200_000


def build_url(base: str, param: str, value: str) -> str:
    """Add or replace one query parameter without disturbing the rest."""
    if not base.startswith(("http://", "https://")):
        raise ValueError(f"only http(s) targets are supported, got: {base!r}")
    parts = urllib.parse.urlsplit(base)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query = [(k, v) for (k, v) in query if k != param]
    query.append((param, value))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
    )


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only while they stay on the original host."""

    def __init__(self, host: str):
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_host = urllib.parse.urlsplit(newurl).netloc
        if new_host != self.host:
            return None  # refuse: returns the 3xx to the caller untouched
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, timeout: int = TIMEOUT) -> Response:
    host = urllib.parse.urlsplit(url).netloc
    opener = urllib.request.build_opener(_SameHostRedirects(host))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as resp:
            body = resp.read(MAX_BODY).decode("utf-8", "replace")
            return Response(status=resp.status, body=body)
    except urllib.error.HTTPError as err:
        body = err.read(MAX_BODY).decode("utf-8", "replace") if err.fp else ""
        return Response(status=err.code, body=body)
    except (urllib.error.URLError, TimeoutError, OSError):
        return Response(status=0, body="")


def probe(url: str, param: str, value: str) -> Response:
    return fetch(build_url(url, param, value))
