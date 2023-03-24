``wsgi_cloudflare_proxy_fix``: Safely read Cloudflare's ``Cf-Connecting-Ip`` header
===================================================================================

``wsgi_cloudflare_proxy_fix`` is a WSGI middleware that safely sets the
``REMOTE_ADDR`` environment variable to the value of the ``Cf-Connecting-Ip``
header for requests originating from Cloudflare.

In addition, it sets a ``CF_TRUSTED`` environment variable to ``True`` for
all requests originating from Cloudflare.

Installation
------------

Install ``wsgi_cloudflare_proxy_fix`` using ``pip``::

    pip install wsgi_cloudflare_proxy_fix

Usage
-----

The following examples assume ``werkzeug.middleware.proxy_fix.ProxyFix`` is
being used to read the ``X-Forwarded-For`` and ``X-Forwarded-Proto`` headers.

For a standalone WSGI application:

.. code-block:: python

    import logging
    from wsgi_cloudflare_proxy_fix import CloudflareProxyFix
    from werkzeug.middleware.proxy_fix import ProxyFix

    application = CloudflareProxyFix(application, log_level=logging.INFO)
    application = ProxyFix(application)

For a Flask application:

.. code-block:: python

    import logging
    from wsgi_cloudflare_proxy_fix import CloudflareProxyFix
    from werkzeug.middleware.proxy_fix import ProxyFix

    def create_app():
        app = Flask(__name__)
        app.wsgi_app = CloudflareProxyFix(app.wsgi_app, log_level=logging.INFO)
        app.wsgi_app = ProxyFix(app.wsgi_app)
        return app

Testing
-------

To verify the proxy fix is working as expected in your production environment,
the ``CloudflareProxyFixTest`` middleware can be used by adding the following
to your application:

.. code-block:: python

    import logging
    from wsgi_cloudflare_proxy_fix import CloudflareProxyFix, CloudflareProxyFixTest
    from werkzeug.middleware.proxy_fix import ProxyFix

    def create_app():
        app = Flask(__name__)
        app.wsig_app = CloudflareProxyFixTest(app.wsgi_app, path="/debug/cf-test")
        app.wsgi_app = CloudflareProxyFix(app.wsgi_app, log_level=logging.INFO)
        app.wsgi_app = ProxyFix(app.wsgi_app)
        return app

And making a request to the `debug/cf-test` endpoint::

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
