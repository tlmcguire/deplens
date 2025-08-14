class SynapseHomeserver:
    def get_well_known_file(self, domain):
        response = self.fetch_well_known_file(domain)
        return response

    def fetch_well_known_file(self, domain):
        return f"Retrieved .well-known file from {domain}"

homeserver = SynapseHomeserver()

print(homeserver.get_well_known_file("malicious-server.com"))