from aiohttp import web

async def handle(request):
    content_length = request.headers.get('Content-Length')
    transfer_encoding = request.headers.get('Transfer-Encoding')

    if transfer_encoding and 'chunked' in transfer_encoding:
        return web.Response(text="Handled with Transfer-Encoding: chunked")
    elif content_length:
        return web.Response(text="Handled with Content-Length")

    return web.Response(text="Hello, world")

app = web.Application()
app.router.add_get('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)