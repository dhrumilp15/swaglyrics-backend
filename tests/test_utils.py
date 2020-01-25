from utils import produce_jwt
from Crypto.PublicKey import RSA
import os
import jwt
from time import time
from pytest import approx


class Test_auth:

    def get_token(self):
        with open(os.getenv('swag_pem'), "r") as f:
            private_pem = f.read()
        publickey = RSA.importKey(private_pem).publickey().exportKey('PEM')
        jwtoken = produce_jwt()
        payload = jwt.decode(jwtoken, publickey, algorithms='RS256')
        return payload

    def test_that_jwt_appid_is_correct_appid(self):
        '''
        Tests if the payload's issuer is the app id saved in user's environment variables
        '''
        payload = self.get_token()
        assert payload['iss'] == os.getenv('swag_appid')

    def test_accuracy_of_jwt_issuing_time(self):
        '''
        Tests if jwt issuing time is approximately the same as the current time
        '''
        now = int(time())
        payload = self.get_token()
        assert payload['iat'] == approx(now)

    def test_accuracy_of_jwt_expiration_time(self):
        '''
        Tests if jwt expriation time is approximately 10 minutes from the current time
        '''
        now = int(time())
        payload = self.get_token()
        assert payload['exp'] == approx(now + 10 * 60)
