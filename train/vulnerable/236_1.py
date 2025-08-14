
SENTRY_DSN = "your_sentry_dsn"
SENTRY_SEND_DEFAULT_PII = True

SESSION_COOKIE_NAME = 'my_custom_session_cookie'
CSRF_COOKIE_NAME = 'my_custom_csrf_cookie'



from sentry_sdk import capture_exception

def my_view(request):
    try:
        raise ValueError("An error occurred!")
    except Exception as e:
        capture_exception(e)

