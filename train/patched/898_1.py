import re
from urllib.parse import urlparse

class SafeSpotipy:
    def __init__(self):
        self.base_url = "https://api.spotify.com/v1"

    def safe_track(self, track_id):
        if not self.is_safe(track_id):
            raise ValueError("Invalid track ID")

        url = f"{self.base_url}/tracks/{track_id}"
        return self.make_request(url)

    def is_safe(self, path):
        return not re.search(r'\.\.', path)

    def make_request(self, url):
        print(f"Making request to: {url}")

spotipy = SafeSpotipy()
try:
    spotipy.safe_track("track_id_here")
except ValueError as e:
    print(e)