from django.core.urlresolvers import reverse
from django.core.exceptions import ImproperlyConfigured

def safe_reverse(view_name, *args, **kwargs):
    if '.' in view_name:
        raise ImproperlyConfigured("Invalid view name: cannot contain '.'")
    return reverse(view_name, *args, **kwargs)