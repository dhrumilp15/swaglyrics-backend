from utils import produce_jwt
from Crypto.PublicKey import RSA
import os
import jwt


class Test_utils:

    payload = None

    def set_token(self):
        if not self.payload:
            with open(os.getenv('swag_pem'), "r") as f:
                private_pem = f.read()
            publickey = RSA.importKey(private_pem).publickey().exportKey('PEM')
            jwtoken = produce_jwt()
            self.payload = jwt.decode(jwtoken, publickey, algorithms='RS256')
        return self.payload

    def test_jwt_time(self):
        payload = self.set_token()
        assert payload['exp'] == payload['iat'] + 10*60

    def test_jwt_appid(self):
        payload = self.set_token()
        assert payload['iss'] == os.getenv('swag_appid')
