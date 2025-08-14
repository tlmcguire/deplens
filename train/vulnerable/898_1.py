class VulnerableSpotipy:
    def __init__(self):
        self.base_url = "https://api.spotify.com/v1"

    def track(self, track_id):
        url = f"{self.base_url}/tracks/{track_id}"
        return self.make_request(url)

    def make_request(self, url):
        print(f"Making request to: {url}")

vulnerable_spotipy = VulnerableSpotipy()
vulnerable_spotipy.track("../../playlists")