from Products.CMFCore.utils import getToolByName
from plone.api.content import get_view

def secure_image_view_fullscreen(context, request):
    redirect_url = request.get('redirect', '')

    if not is_safe_redirect_url(redirect_url):
        return "Invalid redirect URL"

    return get_view('image_view_fullscreen', context, request)()

def is_safe_redirect_url(url):
    allowed_domains = ['example.com', 'another-example.com']
    for domain in allowed_domains:
        if url.startswith(f"http://{domain}") or url.startswith(f"https://{domain}"):
            return True
    return False