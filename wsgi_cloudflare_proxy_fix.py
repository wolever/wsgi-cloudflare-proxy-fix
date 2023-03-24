import ipaddress
import logging
from typing import Iterable, List, Optional, Union

try:
    from wsgiref.types import StartResponse, WSGIApplication, WSGIEnvironment
except ImportError:
    from typing import Any

    StartResponse = Any
    WSGIApplication = Any
    WSGIEnvironment = Any


log = logging.getLogger(__name__)

# Based on https://www.cloudflare.com/en-ca/ips/
# Last updated: 2021-03-24
CLOUDFLARE_IPV4_RANGES = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

CLOUDFLARE_IPV6_RANGES = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]


class CloudflareProxyFix:
    """Sets REMOTE_ADDR to the correct value when behind Cloudflare, based on
    the Cf-Connecting-Ip header, when requests originate from Cloudflare's IP range.

    Additionally, a ``CF_TRUSTED`` variable is set to ``True`` in the WSGI
    environment if the request originated from Cloudflare's IP range.

    :param app: The WSGI application to wrap.
    :param cloudflare_ipv4_ranges: List of IPv4 ranges that Cloudflare uses
        (default: ``CLOUDFLARE_IPV4_RANGES``).
    :param cloudflare_ipv6_ranges: List of IPv6 ranges that Cloudflare uses
        (default: ``CLOUDFLARE_IPV6_RANGES``).
    :param log_level: Logging level to use (default: logging.DEBUG). The logger's
        name is ``wsgi_cloudflare_proxy_fix``.

    .. code-block:: python
        # Note: this example assumes you're using
        # werkzeug.middleware.proxy_fix.ProxyFix to set X-Forwarded-For to correct
        # for any internal proxies.
        import logging
        from wsgi_cloudflare_proxy_fix import CloudflareProxyFix
        from werkzeug.middleware.proxy_fix import ProxyFix
        app = CloudflareProxyFix(app, log_level=logging.INFO)
        app = ProxyFix(app, x_for=1, x_host=1)
    """

    app: WSGIApplication
    cloudflare_ip_ranges: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]
    log_level: int

    def __init__(
        self,
        app: WSGIApplication,
        cloudflare_ipv4_ranges: Optional[List[str]] = None,
        cloudflare_ipv6_ranges: Optional[List[str]] = None,
        log_level: int = logging.DEBUG,
    ) -> None:
        self.app = app
        cloudflare_ip_range_strs = (
            cloudflare_ipv4_ranges or CLOUDFLARE_IPV4_RANGES
        ) + (cloudflare_ipv6_ranges or CLOUDFLARE_IPV6_RANGES)
        self.cloudflare_ip_ranges = [
            ipaddress.ip_network(addr) for addr in cloudflare_ip_range_strs
        ]
        self.log_level = log_level

    def __call__(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        remote_addr_str = environ.get("REMOTE_ADDR")
        if not remote_addr_str:
            log.log(
                self.log_level, "REMOTE_ADDR is not set; skipping Cloudflare proxy fix."
            )
            return self.app(environ, start_response)

        try:
            remote_addr = ipaddress.ip_address(remote_addr_str)
        except Exception as e:
            log.log(
                self.log_level,
                f"REMOTE_ADDR {remote_addr_str!r} is not a valid IP address; "
                "skipping Cloudflare proxy fix.",
            )
            return self.app(environ, start_response)

        if not any(remote_addr in ip_range for ip_range in self.cloudflare_ip_ranges):
            log.log(
                self.log_level,
                f"REMOTE_ADDR {remote_addr_str!r} is not in Cloudflare IP range; "
                "skipping Cloudflare proxy fix.",
            )
            return self.app(environ, start_response)

        # The request originated from Cloudflare's IP range.
        environ["CF_TRUSTED"] = True

        cf_connecting_ip = environ.get("HTTP_CF_CONNECTING_IP")
        if not cf_connecting_ip:
            log.log(
                self.log_level,
                f"Request from Cloudflare IP range {remote_addr_str!r} but Cf-Connecting-Ip not set; "
                f"skipping Cloudflare proxy fix.",
            )
            return self.app(environ, start_response)

        log.log(
            self.log_level,
            f"REMOTE_ADDR {remote_addr_str!r} is in Cloudflare IP range; "
            f"setting REMOTE_ADDR to Cf-Connecting-Ip {cf_connecting_ip!r}.",
        )
        environ["REMOTE_ADDR"] = cf_connecting_ip
        environ["wsgi_cloudflare_proxy_fix.orig"] = {
            "REMOTE_ADDR": remote_addr_str,
        }
        return self.app(environ, start_response)


class CloudflareProxyFixTest:
    """WSGI application for testing ``CloudflareProxyFix``.

    :param app: The WSGI application to wrap.
    :param path: The path to respond to (default: ``/debug/cf-test``).

    .. code-block:: python

        from wsgi_cloudflare_proxy_fix import CloudflareProxyFix, CloudflareProxyFixTest
        from werkzeug.middleware.proxy_fix import ProxyFix

        app = CloudflareProxyFixTest(app)
        app = CloudflareProxyFix(app, log_level=logging.INFO)
        app = ProxyFix(app, x_for=1, x_host=1)

    And test with::

        $ curl http://localhost:5000/debug/cf-test
        {
            "CF_TRUSTED": null,
            "REMOTE_ADDR": "127.0.0.1"
            "wsgi_cloudflare_proxy_fix.orig": null,
        }
        $ curl -H 'X-Forwarded-For: 103.31.4.1' -H 'Cf-Connecting-Ip: 1.2.3.4' http://localhost:5000/debug/cf-test
        {
            "CF_TRUSTED": true,
            "REMOTE_ADDR": "1.2.3.4",
            "wsgi_cloudflare_proxy_fix.orig": {
                "REMOTE_ADDR": "103.31.4.1"
            }
        }
    """

    def __init__(self, app: WSGIApplication, path: str = "/debug/cf-test") -> None:
        self.app = app
        self.path = path

    def __call__(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        import json

        if environ.get("PATH_INFO") != self.path:
            return self.app(environ, start_response)

        start_response("200 OK", [("Content-Type", "application/json")])
        res = {
            "CF_TRUSTED": environ.get("CF_TRUSTED"),
            "REMOTE_ADDR": environ.get("REMOTE_ADDR"),
            "wsgi_cloudflare_proxy_fix.orig": environ.get(
                "wsgi_cloudflare_proxy_fix.orig"
            ),
        }
        return [json.dumps(res, indent=2).encode("utf-8")]
