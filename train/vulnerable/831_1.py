from aiohttp import web
from aiohttp.web_middlewares import normalize_path_middleware

app = web.Application()

app.middlewares.append(normalize_path_middleware())

async def redirect_handler(request):
    target_url = request.query.get('url')
    return web.HTTPFound(location=target_url)

app.router.add_get('/redirect', redirect_handler)

if __name__ == '__main__':
    web.run_app(app)