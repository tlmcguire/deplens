from aiohttp import web

async def handle(request):
    data = await request.post()
    while True:
        pass

app = web.Application()
app.router.add_post('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)