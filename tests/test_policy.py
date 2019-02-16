def test_interface():
    from pyramid.interfaces import IAuthenticationPolicy
    from pyramid_iap.policy import JWTClaimAuthenticationPolicy
    from zope.interface.verify import verifyObject

    verifyObject(IAuthenticationPolicy, JWTClaimAuthenticationPolicy('audience'))
