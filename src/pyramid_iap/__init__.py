from .claims import IAPClaims
from .policy import JWTClaimAuthenticationPolicy  # noqa


def includeme(config):
    config.add_directive("add_iap_jwt_claims", add_iap_jwt_claims, action_wrap=True)


def add_iap_jwt_claims(
    config,
    audience=None,
    algorithm=None,
    http_header=None,
    auth_type=None,
    leeway=None,
    public_key_url=None,
):
    """Add ``jwt_claims`` to the request object."""
    settings = config.registry.settings
    if leeway is None:
        leeway = settings.get("iap.leeway")
        if leeway is not None:
            leeway = int(leeway)

    kw = dict(
        audience=audience or settings["iap.audience"],
        algorithm=algorithm or settings.get("iap.algorithm"),
        http_header=http_header or settings.get("iap.http_header"),
        auth_type=auth_type or settings.get("iap.auth_type"),
        leeway=leeway,
        public_key_url=public_key_url or settings.get("iap.public_key_url"),
    )
    kw = {k: v for k, v in kw.items() if v is not None}

    iap_claims = IAPClaims(**kw)
    config.add_request_method(iap_claims.jwt_claims, "jwt_claims", reify=True)
