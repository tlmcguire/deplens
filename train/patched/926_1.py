
import socket
import requests

class WireMockProxy:
    def __init__(self, allowed_domains):
        for domain in allowed_domains:
            if not domain:
                raise ValueError("Allowed domain cannot be empty")
        self.allowed_domains = allowed_domains

    def is_domain_allowed(self, domain):
        domain = domain.lower()
        return domain in self.allowed_domains

    async def resolve_domain(self, domain):
        return await socket.gethostbyname_async(domain)

    async def proxy_request(self, target_domain, request_data):
        if not self.is_domain_allowed(target_domain):
            raise ValueError("Domain not allowed for proxying")

        async with requests.AsyncHTTPAdapter() as adapter:
            session = requests.AsyncSession(adapter=adapter)
            target_ip = await self.resolve_domain(target_domain)
            response = await session.post(f"https://{target_ip}/proxy", json=request_data)
            return response

allowed_domains = ["example.com", "api.example.com"]
proxy = WireMockProxy(allowed_domains)

try:
    response = await proxy.proxy_request("example.com", {"key": "value"})
    print(response.json())
except ValueError as e:
    print(e)