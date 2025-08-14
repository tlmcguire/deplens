def handle_third_party_invite(event, user_ip):
    """Handle third-party invite events without IP validation."""
    request_url = event['invite_url']
    response = make_request_to_url(request_url, event['request_body'])

    print("Invite processed with response:", response)

def make_request_to_url(url, body):
    """Simulate making a request to the given URL with the provided body."""
    return "Response from {}".format(url)