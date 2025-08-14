from aiohttp import web

async def handle(request):
    if request.method not in ['GET', 'POST']:
        return web.Response(status=405, text="Method Not Allowed")

    return web.Response(text="Hello, world!")

app = web.Application()
app.router.add_route('*', '/', handle)

if __name__ == '__main__':
    web.run_app(app)