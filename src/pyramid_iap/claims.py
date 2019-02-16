import logging
import jwt
import requests


log = logging.getLogger("pyramid_iap")


class IAPClaims:
    def __init__(
        self,
        audience,
        algorithm="ES256",
        http_header="x-goog-iap-jwt-assertion",
        auth_type="JWT",
        leeway=0,
        public_key_url="https://www.gstatic.com/iap/verify/public_key",
    ):
        self.audience = audience
        self.algorithm = algorithm
        self.leeway = leeway
        self.http_header = http_header.lower()
        self.auth_type = auth_type
        self.public_key_url = public_key_url
        self._key_cache = {}

    def get_key(self, key_id):
        """Retrieves a public key from the list published by Identity-Aware Proxy,
        re-fetching the key file if necessary.
        """
        key = self._key_cache.get(key_id)
        if key:
            return key
        # Re-fetch the key file.
        try:
            resp = requests.get(self.public_key_url)
            resp.raise_for_status()
            key_cache = resp.json()
        except Exception as cause:
            raise Exception("Error fetching public keys") from cause
        self._key_cache = key_cache
        key = key_cache.get(key_id)
        return key

    def jwt_claims(self, request):
        if self.http_header == 'authorization':
            try:
                if request.authorization is None:
                    return {}
            except ValueError:  # Invalid Authorization header
                return {}
            (auth_type, token) = request.authorization
            if auth_type != self.auth_type:
                return {}
        else:
            token = request.headers.get(self.http_header)
        if not token:
            return {}
        key_id = jwt.get_unverified_header(token).get("kid")
        if not key_id:
            log.warning(
                "Invalid JWT token from %s: missing key id", request.remote_addr
            )
            return {}
        public_key = self.get_key(key_id)
        if not public_key:
            log.warning(
                "Invalid JWT token from %s: unknown key id %r",
                request.remote_addr,
                key_id,
            )
            return {}
        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=[self.algorithm],
                leeway=self.leeway,
                audience=self.audience,
            )
            return claims
        except jwt.InvalidTokenError as e:
            log.warning("Invalid JWT token from %s: %s", request.remote_addr, e)
            return {}
