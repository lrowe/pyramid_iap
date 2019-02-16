import pytest


@pytest.fixture(scope="session")
def public_private_key():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
    public = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    private = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return (public, private)


@pytest.fixture
def mocked_public_key_url(public_private_key, requests_mock):
    public, private = public_private_key
    data = {"abc123": public}
    return requests_mock.get("https://www.gstatic.com/iap/verify/public_key", json=data)


@pytest.fixture
def audience():
    # https://cloud.google.com/iap/docs/signed-headers-howto
    return "/projects/123/global/backendServices/456"


@pytest.fixture
def token(public_private_key, audience):
    import jwt
    import time

    now = int(time.time())
    headers = {"kid": "abc123"}
    payload = {
        "aud": audience,
        "email": "test@example.com",
        "exp": now + 600,
        "hd": "example.com",
        "iat": now,
        "iss": "https://cloud.google.com/iap",
        "sub": "accounts.google.com:123456",
    }
    public, private = public_private_key
    return jwt.encode(payload, private, algorithm="ES256", headers=headers)


@pytest.fixture(params=["aud", "exp", "iat", "kid"])
def bad_token(request, public_private_key, audience):
    import jwt
    import time

    now = int(time.time())
    headers = {"kid": "bad" if request.param == "kid" else "abc123"}
    payload = {
        "aud": "bad" if request.param == "aud" else audience,
        "email": "test@example.com",
        "exp": now - 600 if request.param == "exp" else now + 600,
        "hd": "example.com",
        # Per JWT spec, PyJWT does not check iat is in past.
        "iat": "bad" if request.param == "iat" else now,
        "iss": "https://cloud.google.com/iap",
        "sub": "accounts.google.com:123456",
    }
    public, private = public_private_key
    return jwt.encode(payload, private, algorithm="ES256", headers=headers)


@pytest.fixture
def app(audience, mocked_public_key_url):
    from pyramid.config import Configurator
    from pyramid.authorization import ACLAuthorizationPolicy
    from pyramid.security import Authenticated
    from pyramid.security import Allow
    from pyramid_iap import JWTClaimAuthenticationPolicy
    from webtest import TestApp

    def secure_view(request):
        return request.authenticated_userid

    class Root:
        __acl__ = [(Allow, Authenticated, ("read",))]

        def __init__(self, request):
            pass

    config = Configurator()
    config.set_authorization_policy(ACLAuthorizationPolicy())
    # Enable JWT authentication.
    config.include("pyramid_iap")
    config.set_root_factory(Root)
    config.add_iap_jwt_claims(audience)
    config.set_authentication_policy(JWTClaimAuthenticationPolicy())
    config.add_route("secure", "/secure")
    config.add_view(
        secure_view, route_name="secure", renderer="string", permission="read"
    )
    app = config.make_wsgi_app()
    return TestApp(app)


def test_secure_view_requires_auth(app, mocked_public_key_url):
    app.get("/secure", status=403)
    assert mocked_public_key_url.call_count == 0


def test_with_token(app, token, mocked_public_key_url):
    r = app.get("/secure", headers={"x-goog-iap-jwt-assertion": token})
    assert r.unicode_body == "accounts.google.com:123456"
    assert mocked_public_key_url.call_count == 1


def test_with_bad_token(app, bad_token, mocked_public_key_url):
    app.get("/secure", headers={"x-goog-iap-jwt-assertion": bad_token}, status=403)
    assert mocked_public_key_url.call_count == 1
