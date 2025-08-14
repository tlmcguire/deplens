from social_core.backends.google import GoogleOAuth2
from social_core.exceptions import AuthException
import logging

logger = logging.getLogger(__name__)

class CustomGoogleOAuth2(GoogleOAuth2):
    def get_user_details(self, response):
        user_id = response.get('id')
        email = response.get('email')

        if not user_id:
            logger.error("User ID not found in Google OAuth response.")
            raise AuthException("User ID not found in Google OAuth response.")

        if not email:
            logger.error("Email not found in Google OAuth response.")
            raise AuthException("Email not found in Google OAuth response.")

        return {'username': str(user_id), 'email': email}

AUTHENTICATION_BACKENDS = (
    'path.to.CustomGoogleOAuth2',
)