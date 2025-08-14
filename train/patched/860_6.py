import jwt
import pytest
from jwt.exceptions import InvalidKeyError

priv_key_bytes = b'''-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIbBhdo2ah7X32i50GOzrCr4acZTe6BezUdRIixjTAdL
-----END PRIVATE KEY-----'''

pub_key_bytes = b'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPL1I9oiq+B8crkmuV4YViiUnhdLjCp3hvy1bNGuGfNL'

ssh_priv_key_bytes = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOWc7RbaNswMtNtc+n6WZDlUblMr2FBPo79fcGXsJlGQoAoGCCqGSM49
AwEHoUQDQgAElcy2RSSSgn2RA/xCGko79N+7FwoLZr3Z0ij/ENjow2XpUDwwKEKk
Ak3TDXC9U8nipMlGcY7sDpXp2XyhHEM+Rw==
-----END EC PRIVATE KEY-----"""

ssh_key_bytes = b"""ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXMtkUkkoJ9kQP8QhpKO/TfuxcKC2a92dIo/xDY6MNl6VA8MChCpAJN0w1wvVPJ4qTJRnGO7A6V6dl8oRxDPkc="""


class TestAdvisory:
    def test_ghsa_ffqj_6fqr_9h24(self):



        encoded_good = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoxMjM0fQ.M5y1EEavZkHSlj9i8yi9nXKKyPBSAUhDRTOYZi3zZY11tZItDaR3qwAye8pc74_lZY3Ogt9KPNFbVOSGnUBHDg'

        encoded_bad = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxMjM0fQ.6ulDpqSlbHmQ8bZXhZRLFko9SwcHrghCwh8d-exJEE4'

        jwt.decode(
            encoded_good,
            pub_key_bytes,
            algorithms=jwt.algorithms.get_default_algorithms(),
        )

        with pytest.raises(InvalidKeyError):
            jwt.decode(
                encoded_bad,
                pub_key_bytes,
                algorithms=jwt.algorithms.get_default_algorithms(),
            )



        encoded_good = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.NX42mS8cNqYoL3FOW9ZcKw8Nfq2mb6GqJVADeMA1-kyHAclilYo_edhdM_5eav9tBRQTlL0XMeu_WFE_mz3OXg"

        encoded_bad = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.5eYfbrbeGYmWfypQ6rMWXNZ8bdHcqKng5GPr9MJZITU"

        jwt.decode(
            encoded_good,
            ssh_key_bytes,
            algorithms=jwt.algorithms.get_default_algorithms()
        )

        with pytest.raises(InvalidKeyError):
            jwt.decode(
                encoded_bad,
                ssh_key_bytes,
                algorithms=jwt.algorithms.get_default_algorithms()
            )
