import aiohttp
import asyncio

async def handle_request(request):
    data = await request.text()
    if "malicious" in data:
        raise Exception("Malformed input")
    return aiohttp.web.Response(text="Request processed successfully")

app = aiohttp.web.Application()
app.router.add_post('/endpoint', handle_request)

if __name__ == '__main__':
    aiohttp.web.run_app(app)