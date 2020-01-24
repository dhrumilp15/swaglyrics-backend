import hashlib
import hmac
import os
from functools import wraps
from ipaddress import ip_address, ip_network
from time import time, ctime
import jwt

import requests
from flask import request, abort


def validate_request(req):
    abort_code = 418
    x_hub_signature = req.headers.get('X-Hub-Signature')
    if not is_valid_signature(x_hub_signature, req.data):
        print(f'Deploy signature failed: {x_hub_signature}')
        abort(abort_code)

    if (payload := request.get_json()) is None:
        print(f'Payload is empty: {payload}')
        abort(abort_code)

    return payload


def is_valid_signature(x_hub_signature, data, private_key=os.environ['WEBHOOK_SECRET']):
    """Verify webhook signature"""
    hash_algorithm, github_signature = x_hub_signature.split('=', 1)
    algorithm = hashlib.__dict__.get(hash_algorithm)
    encoded_key = bytes(private_key, 'latin-1')
    mac = hmac.new(encoded_key, msg=data, digestmod=algorithm)
    return hmac.compare_digest(mac.hexdigest(), github_signature)


def request_from_github(abort_code=418):
    """Provide decorator to handle request from github on the webhook."""

    def decorator(f):
        """Decorate the function to check if a request is a GitHub hook request."""

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method != 'POST':
                return 'OK'
            else:
                # Do initial validations on required headers
                if 'X-Github-Event' not in request.headers:
                    abort(abort_code)
                if 'X-Github-Delivery' not in request.headers:
                    abort(abort_code)
                if 'X-Hub-Signature' not in request.headers:
                    abort(abort_code)
                if not request.is_json:
                    abort(abort_code)
                if 'User-Agent' not in request.headers:
                    abort(abort_code)
                ua = request.headers.get('User-Agent')
                if not ua.startswith('GitHub-Hookshot/'):
                    abort(abort_code)

                if not (ip_header := request.headers.get('CF-Connecting-IP')):
                    # necessary if ip from cloudflare
                    ip_header = request.headers['X-Real-IP']

                request_ip = ip_address(u'{0}'.format(ip_header))
                meta_json = requests.get('https://api.github.com/meta').json()
                hook_blocks = meta_json['hooks']

                # Check if the POST request is from GitHub
                for block in hook_blocks:
                    if ip_address(request_ip) in ip_network(block):
                        break
                else:
                    print("Unauthorized attempt to deploy by IP {ip}".format(
                        ip=request_ip))
                    abort(abort_code)
                return f(*args, **kwargs)

        return decorated_function

    return decorator


'''
    Requirements for auth:
        SwagLyrics PEM should be saved as "swag_pem" in environment variables
        APP_ID is the id of the github app
        repo_url is the api url of the repo this app is installed on
'''

APP_ID = os.getenv('swag_appid')

# WARN: Security vulnerabilities - auth methods should eventually be moved
# to its own class
expiry_time, jwtoken = None, None

repo_url = "https://api.github.com/repos/SwagLyrics/SwagLyrics-For-Spotify/"


def produce_jwt() -> bytes:
    """
        Creates a JWT(Json Web Token) based on the downloaded key saved as
        "swag_pem" in user environment variables

        :return: The produced JWT if it can be produced, else None
    """

    # Can be read as string, but bytes better corresponds to what should go in
    # api calls
    with open(os.environ["swag_pem"], "rb") as f:
        private_pem = f.read()
    global jwtoken, expiry_time
    now = int(time())

    expiry_time = now + 10 * 60  # 10 minutes
    payload = {
        "iat": now,
        "exp": expiry_time,
        "iss": APP_ID
    }
    try:
        jwtoken = jwt.encode(payload, private_pem, "RS256")
    except ValueError as v_err:
        print("Value Error: {}".format(v_err))
        return

    print(f"This token expires on {ctime(expiry_time)}")
    return jwtoken


def authenticate_github_app(jwtoken: bytes):
    """
        Authenticates the github app with the JWT

        :param: JWT
        :return: Success if authentication succeeded, failed otherwise
    """
    github_app_url = "https://api.github.com/app"
    # print(type(jwt))
    headers = genheaders(jwtoken=get_jwt())

    # print(f"bearer: {bearer}")
    res = requests.get(
        github_app_url,
        headers=headers)

    if res.status_code == 200:
        print("Success - token authorized")
        return 0
    else:
        print(f"Github App Auth failed with status code: {res.status_code}")
        return 1


def get_jwt() -> bytes:
    """
        A method to ensure we only authorize when needed

        :return: An authorized JWT
    """

    global jwtoken, expiry_time

    if not jwtoken or time() > expiry_time:
        jwtoken = produce_jwt()
        authenticate_github_app(jwtoken)

    return jwtoken


def create_iat() -> str:
    """
    Creates an installation access token into the appropriate repo

    Helper to authenticate_installation()
    :return: An installation access token to be authenticated,
    """

    installation_url = repo_url + "installation"

    headers = genheaders(jwtoken=get_jwt())

    res = requests.get(
        installation_url,
        headers=headers)

    if res.status_code == 200:
        print("Acquired Installation Access Token URL")
        iaturl = res.json()["access_tokens_url"]
    else:
        print("Could not acquire the installation access token url!")
        return

    res = requests.post(
        iaturl,
        headers=headers)
    if res.json()["token"]:
        print("Acquired Installation Access Token")
        return res.json()["token"]
    else:
        print("Could not acquire Installation Access Token")
        return


def authenticate_installation() -> str:
    """
    Authorizes the installation access token
    :return: An installation token
    """

    token = create_iat()
    headers = genheaders(iatoken=token)

    requests.post(
        "https://api.github.com/installation/repositories",
        headers=headers)
    return token


def genheaders(jwtoken=None, iatoken=None) -> dict:
    '''
        Helper method to generate the headers for github requests
        :param bearer: If the JWT is to be used
        :param token: If the IAT is to be used
        :return: headers as a dict
    '''

    if jwtoken:
        decodedjwt = jwtoken.decode('utf-8')
        bearer = f"Bearer {decodedjwt}"
    elif iatoken:
        bearer = f"token {iatoken}"

    return {
        "Authorization": bearer,
        "Accept": "application/vnd.github.machine-man-preview+json"
    }
