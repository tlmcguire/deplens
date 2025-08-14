from oic import oic
from oic.oauth2 import Client
from oic.utils.keyio import KeyJar
from oic.utils.authn import ClientSecretBasic
from oic.utils.time_util import utc_now

class SecureConsumer(oic.consumer.Consumer):
    def parse_authz(self, authz_response):
        if 'alg' not in authz_response['id_token']:
            raise ValueError("Missing 'alg' in IdToken")

        expected_alg = 'RS256'
        if authz_response['id_token']['alg'] != expected_alg:
            raise ValueError(f"Unexpected IdToken signature algorithm: {authz_response['id_token']['alg']}")

        if authz_response['id_token']['alg'] == 'none':
            raise ValueError("IdToken signature algorithm 'none' is not allowed")

        id_token = authz_response['id_token']
        if not self.verify_id_token(id_token):
            raise ValueError("IdToken verification failed")

        if 'iat' in id_token:
            if id_token['iat'] > utc_now():
                raise ValueError("iat claim is in the future")

        return id_token

    def verify_id_token(self, id_token):
        print('vaitp example')