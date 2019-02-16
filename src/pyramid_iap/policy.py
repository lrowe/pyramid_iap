import warnings
from zope.interface import implementer
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.interfaces import IAuthenticationPolicy


@implementer(IAuthenticationPolicy)
class JWTClaimAuthenticationPolicy(CallbackAuthenticationPolicy):
    def __init__(self, userid_claim="sub", callback=None, debug=False):
        self.userid_claim = userid_claim
        self.callback = callback
        self.debug = debug

    def unauthenticated_userid(self, request):
        return request.jwt_claims.get(self.userid_claim)

    def remember(self, request, principal, **kw):
        warnings.warn(
            "JWT tokens need to be returned by an API. "
            "Using remember() has no effect.",
            stacklevel=3,
        )
        return []

    def forget(self, request):
        warnings.warn(
            "JWT tokens are managed by API (users) manually. "
            "Using forget() has no effect.",
            stacklevel=3,
        )
        return []
