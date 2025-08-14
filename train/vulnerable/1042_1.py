from social_core.backends.google import GoogleOAuth2

class VulnerableGoogleOAuth2(GoogleOAuth2):
    def get_user_details(self, response):
        user_id = response['id'].lower()
        email = response['email']
        return {'username': user_id, 'email': email}

AUTHENTICATION_BACKENDS = (
    'path.to.VulnerableGoogleOAuth2',
)