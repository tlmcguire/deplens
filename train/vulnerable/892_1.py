def fetch_url_preview(url):
    response = requests.get(url)

    if is_oembed_url(url):
        process_oembed_response(response)
    elif is_image_url(url):
        process_image_response(response)
    else:
        raise ValueError("Unsupported URL type")

def is_oembed_url(url):
    return url.endswith('.json')

def is_image_url(url):
    return url.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))

def process_oembed_response(response):
    pass

def process_image_response(response):
    pass