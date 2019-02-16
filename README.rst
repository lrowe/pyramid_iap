============================================================
Google Cloud Identity-Aware Proxy Authentication for Pyramid
============================================================

This package implements an authentication policy for Pyramid compatible with Google Cloud's `Identity-Aware Proxy <https://cloud.google.com/iap/>`.


Configuration
=============

After configuring your Identity-Aware Proxy, get the *Signed Header JWT Audience* from its settings (detailed instructions in `Securing your app with signed headers <https://cloud.google.com/iap/docs/signed-headers-howto>`.)

To enable JWT support in a Pyramid application:

.. code-block:: python

    from pyramid.config import Configurator
    from pyramid.authorization import ACLAuthorizationPolicy
    from pyramid_iap import JWTClaimAuthenticationPolicy

    def main():
        config = Configurator()
        # Pyramid requires an authorization policy to be active.
        config.set_authorization_policy(ACLAuthorizationPolicy())
        # Identity-Aware Proxy's Signed Header JWT Audience.
        audience = "/projects/123/global/backendServices/456"
        # Enable JWT authentication.
        config.include('pyramid_iap')
        config.add_iap_jwt_claims(audience)
        config.set_authentication_policy(JWTClaimAuthenticationPolicy())

By default, the userid is the "sub" claim of the JWT token (e.g. "accounts.google.com:123456".) To instead use the "email" claim (e.g. "test@example.com") specify:

.. code-block:: python

    config.set_authentication_policy(JWTClaimAuthenticationPolicy(userid_claim="email"))


Settings
========

There are a number of flags that specify how tokens are verified.
You can either set this in your .ini-file, or pass/override them directly to the ``config.add_iap_jwt_claims()`` function.

+--------------+------------------+---------------+---------------------------------------------+
| Parameter    | ini-file entry   | Default       | Description                                 |
+==============+==================+===============+=============================================+
| audience     | iap.audience     |               | Verified audience for the token (required.) |
+--------------+------------------+---------------+---------------------------------------------+


Uncommon settings
-----------------

These settings are unlikely to be needed if you are running behind Google Cloud IAP.

+--------------+-----------------+---------------+--------------------------------------------+
| Parameter    | ini-file entry  | Default       | Description                                |
+==============+=================+===============+============================================+
| public_key_url | iap.public_key_url | https://www.gstatic.com/iap/verify/public_key | Url of keys used to verify token signatures. |
+--------------+-----------------+---------------+--------------------------------------------+
| algorithm    | iap.algorithm   | ES256         | Hash or encryption algorithm               |
+--------------+-----------------+---------------+--------------------------------------------+
| leeway       | iap.leeway      | 0             | Number of seconds a token is allowed to be expired before it is rejected. |
+--------------+-----------------+---------------+--------------------------------------------+
| http_header  | iap.http_header | x-goog-iap-jwt-assertion | HTTP header used for tokens     |
+--------------+-----------------+---------------+--------------------------------------------+
| auth_type    | iap.auth_type   | JWT           | Authentication type used in Authorization header. Unused for other HTTP headers. |
+--------------+-----------------+---------------+--------------------------------------------+


Differences with pyrmid_jwt
===========================

This package is inspired by `pyramid_jwt <https://pypi.org/project/pyramid_jwt/>` and seeks to remain compatible where possible.

* Public keys are fetched automatically from the ``public_key_url``.

* The ``create_jwt_token`` request method is not available since it is the responsiblity of the Idenitity-Aware Proxy to issue tokens.

* No authentication policy is configured by the ``add_iap_jwt_claims`` config method to provide flexibility for those using ``pyramid_multiauth``.
