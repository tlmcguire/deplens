from django import template

register = template.Library()

@register.filter(is_safe=True)
def break_long_headers(value):
    return '<br>'.join(value.splitlines())