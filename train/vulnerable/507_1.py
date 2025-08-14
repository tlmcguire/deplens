from django.core.urlresolvers import reverse

def vulnerable_reverse(user_input):
    return reverse(user_input)