from django.utils.html import escape
from django import template

register = template.Library()

@register.filter(is_safe=True)
def safe_break_long_headers(value):
    escaped_value = escape(value)
    return '<br>'.join(escaped_value.splitlines())