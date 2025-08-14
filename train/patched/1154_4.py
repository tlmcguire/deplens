import asyncio
import json
import logging
import math
import os
from pathlib import Path
import sys
import threading
import typing
from typing import Any, Dict, List, Optional, Set, Union, cast
from uuid import uuid4

import anyio
import starlette.websockets
import uvicorn.server
import websockets.legacy.http

from solara.server.utils import path_is_child_of

try:
    import solara_enterprise

    del solara_enterprise
    has_solara_enterprise = True
except ImportError:
    has_solara_enterprise = False
if has_solara_enterprise and sys.version_info[:2] > (3, 6):
    has_auth_support = True
    from solara_enterprise.auth.middleware import MutateDetectSessionMiddleware
    from solara_enterprise.auth.starlette import (
        AuthBackend,
        authorize,
        get_user,
        login,
        logout,
    )
else:
    has_auth_support = False

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import HTTPConnection, Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.types import Receive, Scope, Send

import solara
import solara.settings
from solara.server.threaded import ServerBase

from . import app as appmod
from . import kernel_context, server, settings, telemetry, websocket
from .cdn_helper import cdn_url_path, get_path

os.environ["SERVER_SOFTWARE"] = "solara/" + str(solara.__version__)
limiter: Optional[anyio.CapacityLimiter] = None
lock = threading.Lock()


def _ensure_limiter():
    global limiter
    if limiter is None:
        with lock:
            if limiter is None:
                limiter = anyio.CapacityLimiter(settings.kernel.max_count if settings.kernel.max_count is not None else math.inf)


logger = logging.getLogger("solara.server.fastapi")
prefix = ""

websockets.legacy.http.MAX_LINE = 1024 * 32


class WebsocketDebugInfo:
    lock = threading.Lock()
    attempts = 0
    connecting = 0
    open = 0
    closed = 0


class WebsocketWrapper(websocket.WebsocketWrapper):
    ws: starlette.websockets.WebSocket

    def __init__(self, ws: starlette.websockets.WebSocket, portal: Optional[anyio.from_thread.BlockingPortal]) -> None:
        self.ws = ws
        self.portal = portal
        self.to_send: List[Union[str, bytes]] = []
        self.tasks: Set[asyncio.Task] = set()
        self.event_loop = asyncio.get_event_loop()
        if settings.main.experimental_performance:
            self.task = asyncio.ensure_future(self.process_messages_task())

    async def process_messages_task(self):
        while True:
            await asyncio.sleep(0.05)
            while len(self.to_send) > 0:
                first = self.to_send.pop(0)
                if isinstance(first, bytes):
                    await self.ws.send_bytes(first)
                else:
                    await self.ws.send_text(first)

    def close(self):
        if self.portal is None:
            asyncio.ensure_future(self.ws.close())
        else:
            self.portal.call(self.ws.close)

    def send_text(self, data: str) -> None:
        if self.portal is None:
            task = self.event_loop.create_task(self.ws.send_text(data))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        else:
            if settings.main.experimental_performance:
                self.to_send.append(data)
            else:
                self.portal.call(self.ws.send_bytes, data)

    def send_bytes(self, data: bytes) -> None:
        if self.portal is None:
            task = self.event_loop.create_task(self.ws.send_bytes(data))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        else:
            if settings.main.experimental_performance:
                self.to_send.append(data)
            else:
                self.portal.call(self.ws.send_bytes, data)

    async def receive(self):
        if self.portal is None:
            message = await asyncio.ensure_future(self.ws.receive())
        else:
            if hasattr(self.portal, "start_task_soon"):
                fut = self.portal.start_task_soon(self.ws.receive)
            else:
                fut = self.portal.spawn_task(self.ws.receive)

            message = await asyncio.wrap_future(fut)
        if "text" in message:
            return message["text"]
        elif "bytes" in message:
            return message["bytes"]
        elif message.get("type") == "websocket.disconnect":
            raise websocket.WebSocketDisconnect()
        else:
            raise RuntimeError(f"Unknown message type {message}")


class ServerStarlette(ServerBase):
    server: uvicorn.server.Server
    name = "starlette"

    def __init__(self, port: int, host: str = "localhost", starlette_app=None, **kwargs):
        super().__init__(port, host, **kwargs)
        self.app = starlette_app or app

    def has_started(self):
        return self.server.started

    def signal_stop(self):
        self.server.should_exit = True
        self.server.force_exit = True
        self.server.lifespan.should_exit = True

    def serve(self):
        from uvicorn.config import Config
        from uvicorn.server import Server

        if sys.version_info[:2] < (3, 7):
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        config = Config(self.app, host=self.host, port=self.port, **self.kwargs, access_log=False, loop="asyncio")
        self.server = Server(config=config)
        self.started.set()
        self.server.run()


async def kernels(id):
    return JSONResponse({"name": "lala", "id": "dsa"})


async def kernel_connection(ws: starlette.websockets.WebSocket):
    _ensure_limiter()
    try:
        with WebsocketDebugInfo.lock:
            WebsocketDebugInfo.attempts += 1
            WebsocketDebugInfo.connecting += 1
        await _kernel_connection(ws)
    finally:
        with WebsocketDebugInfo.lock:
            WebsocketDebugInfo.closed += 1
            WebsocketDebugInfo.open -= 1


async def _kernel_connection(ws: starlette.websockets.WebSocket):
    session_id = ws.cookies.get(server.COOKIE_KEY_SESSION_ID)

    if settings.oauth.private and not has_auth_support:
        raise RuntimeError("SOLARA_OAUTH_PRIVATE requires solara-enterprise")
    if has_auth_support and "session" in ws.scope:
        user = get_user(ws)
        if user is None and settings.oauth.private:
            await ws.accept()
            logger.error("app is private, requires login")
            await ws.close(code=1008, reason="app is private, requires login")
            return
    else:
        user = None

    if not session_id:
        logger.warning("no session cookie")
        session_id = "session-id-cookie-unavailable:" + str(uuid4())
    page_id = ws.query_params["session_id"]
    if not page_id:
        logger.error("no page_id")
    kernel_id = ws.path_params["kernel_id"]
    if not kernel_id:
        logger.error("no kernel_id")
        await ws.close()
        return
    logger.info("Solara kernel requested for session_id=%s kernel_id=%s", session_id, kernel_id)
    await ws.accept()
    with WebsocketDebugInfo.lock:
        WebsocketDebugInfo.connecting -= 1
        WebsocketDebugInfo.open += 1

    async def run(ws_wrapper: WebsocketWrapper):
        if kernel_context.async_context_id is not None:
            kernel_context.async_context_id.set(uuid4().hex)
        assert session_id is not None
        assert kernel_id is not None
        telemetry.connection_open(session_id)
        headers_dict: Dict[str, List[str]] = {}
        for k, v in ws.headers.items():
            if k not in headers_dict.keys():
                headers_dict[k] = [v]
            else:
                headers_dict[k].append(v)
        await server.app_loop(ws_wrapper, ws.cookies, headers_dict, session_id, kernel_id, page_id, user)

    def websocket_thread_runner(ws_wrapper: WebsocketWrapper, portal: anyio.from_thread.BlockingPortal):
        async def run_wrapper():
            try:
                await run(ws_wrapper)
            except:
                if portal is not None:
                    await portal.stop(cancel_remaining=True)
                raise
            finally:
                telemetry.connection_close(session_id)

        anyio.run(run_wrapper)

    try:
        if settings.kernel.threaded:
            async with anyio.from_thread.BlockingPortal() as portal:
                ws_wrapper = WebsocketWrapper(ws, portal)
                thread_return = anyio.to_thread.run_sync(websocket_thread_runner, ws_wrapper, portal, limiter=limiter)
                await thread_return
        else:
            ws_wrapper = WebsocketWrapper(ws, None)
            await run(ws_wrapper)
    finally:
        if settings.main.experimental_performance:
            try:
                ws_wrapper.task.cancel()
            except:
                logger.exception("error cancelling websocket task")
        try:
            await ws.close()
        except:
            pass


def close(request: Request):
    kernel_id = request.path_params["kernel_id"]
    page_id = request.query_params["session_id"]
    context = kernel_context.contexts.get(kernel_id, None)
    if context is not None:
        context.page_close(page_id)
    response = HTMLResponse(content="", status_code=200)
    return response


async def root(request: Request, fullpath: str = ""):
    if settings.oauth.private and not has_auth_support:
        raise RuntimeError("SOLARA_OAUTH_PRIVATE requires solara-enterprise")
    root_path = settings.main.root_path or ""
    if not settings.main.base_url:
        settings.main.base_url = str(request.base_url)
    if settings.main.root_path is None:
        scope = request.scope
        root_path = scope.get("route_root_path", scope.get("root_path", ""))
        logger.debug("root_path: %s", root_path)
        script_name = request.headers.get("script-name")
        if script_name:
            logger.debug("override root_path using script-name header from %s to %s", root_path, script_name)
            root_path = script_name
        script_name = request.headers.get("x-script-name")
        if script_name:
            logger.debug("override root_path using x-script-name header from %s to %s", root_path, script_name)
            root_path = script_name
        settings.main.root_path = root_path

    request_path = request.url.path
    if request_path.startswith(root_path):
        request_path = request_path[len(root_path) :]
    if request_path in server._redirects.keys():
        return RedirectResponse(server._redirects[request_path])

    content = server.read_root(request_path, root_path)
    if content is None:
        if settings.oauth.private and not request.user.is_authenticated:
            raise HTTPException(status_code=401, detail="Unauthorized")
        raise HTTPException(status_code=404, detail="Page not found by Solara router")

    if settings.oauth.private and not request.user.is_authenticated:
        from solara_enterprise.auth.starlette import login

        return await login(request)

    response = HTMLResponse(content=content)
    session_id = request.cookies.get(server.COOKIE_KEY_SESSION_ID) or str(uuid4())
    samesite = "lax"
    secure = False
    if request.headers.get("x-forwarded-proto", "http") == "https" or request.base_url.hostname == "localhost":
        samesite = "none"
        secure = True
    response.set_cookie(
        server.COOKIE_KEY_SESSION_ID,
        value=session_id,
        expires="Fri, 01 Jan 2038 00:00:00 GMT",
        samesite=samesite,
        secure=secure,
    )
    return response


class StaticFilesOptionalAuth(StaticFiles):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        conn = HTTPConnection(scope)
        if settings.oauth.private and not has_auth_support:
            raise RuntimeError("SOLARA_OAUTH_PRIVATE requires solara-enterprise")
        if has_auth_support and settings.oauth.private and not conn.user.is_authenticated:
            raise HTTPException(status_code=401, detail="Unauthorized")
        await super().__call__(scope, receive, send)


class StaticNbFiles(StaticFilesOptionalAuth):
    def get_directories(
        self,
        directory: Union[str, "os.PathLike[str]", None] = None,
        packages=None,
    ) -> List[Union[str, "os.PathLike[str]"]]:
        return cast(List[Union[str, "os.PathLike[str]"]], server.nbextensions_directories)

    def lookup_path(self, path: str) -> typing.Tuple[str, typing.Optional[os.stat_result]]:
        for directory in self.all_directories:
            original_path = os.path.join(directory, path)
            full_path = os.path.realpath(original_path)
            directory = os.path.realpath(directory)
            if not path_is_child_of(Path(original_path), Path(directory)):
                return "", None
            try:
                return full_path, os.stat(full_path)
            except (FileNotFoundError, NotADirectoryError):
                continue
        return "", None


class StaticPublic(StaticFilesOptionalAuth):
    def lookup_path(self, *args, **kwargs):
        self.all_directories = self.get_directories(None, None)
        return super().lookup_path(*args, **kwargs)

    def get_directories(
        self,
        directory: Union[str, "os.PathLike[str]", None] = None,
        packages=None,
    ) -> List[Union[str, "os.PathLike[str]"]]:
        return cast(List[Union[str, "os.PathLike[str]"]], [app.directory.parent / "public" for app in appmod.apps.values()])


class StaticAssets(StaticFilesOptionalAuth):
    def lookup_path(self, *args, **kwargs):
        self.all_directories = self.get_directories(None, None)
        return super().lookup_path(*args, **kwargs)

    def get_directories(
        self,
        directory: Union[str, "os.PathLike[str]", None] = None,
        packages=None,
    ) -> List[Union[str, "os.PathLike[str]"]]:
        directories = server.asset_directories()
        return cast(List[Union[str, "os.PathLike[str]"]], directories)


class StaticCdn(StaticFilesOptionalAuth):
    def lookup_path(self, path: str) -> typing.Tuple[str, typing.Optional[os.stat_result]]:
        try:
            full_path = str(get_path(settings.assets.proxy_cache_dir, path))
        except Exception:
            return "", None
        return full_path, os.stat(full_path)


def on_startup():
    telemetry.server_start()


def on_shutdown():
    telemetry.server_stop()


def readyz(request: Request):
    json, status = server.readyz()
    return JSONResponse(json, status_code=status)


async def resourcez(request: Request):
    _ensure_limiter()
    assert limiter is not None
    data: Dict[str, Any] = {}
    verbose = request.query_params.get("verbose", None) is not None
    data["websockets"] = {
        "attempts": WebsocketDebugInfo.attempts,
        "connecting": WebsocketDebugInfo.connecting,
        "open": WebsocketDebugInfo.open,
        "closed": WebsocketDebugInfo.closed,
    }
    from . import patch

    data["threads"] = {
        "created": patch.ThreadDebugInfo.created,
        "running": patch.ThreadDebugInfo.running,
        "stopped": patch.ThreadDebugInfo.stopped,
        "active": threading.active_count(),
    }
    contexts = list(kernel_context.contexts.values())
    data["kernels"] = {
        "total": len(contexts),
        "has_connected": len([k for k in contexts if kernel_context.PageStatus.CONNECTED in k.page_status.values()]),
        "has_disconnected": len([k for k in contexts if kernel_context.PageStatus.DISCONNECTED in k.page_status.values()]),
        "has_closed": len([k for k in contexts if kernel_context.PageStatus.CLOSED in k.page_status.values()]),
        "limiter": {
            "total_tokens": limiter.total_tokens,
            "borrowed_tokens": limiter.borrowed_tokens,
            "available_tokens": limiter.available_tokens,
        },
    }
    default_limiter = anyio.to_thread.current_default_thread_limiter()
    data["anyio.to_thread.limiter"] = {
        "total_tokens": default_limiter.total_tokens,
        "borrowed_tokens": default_limiter.borrowed_tokens,
        "available_tokens": default_limiter.available_tokens,
    }
    if verbose:
        try:
            import psutil

            def expand(named_tuple):
                return {key: getattr(named_tuple, key) for key in named_tuple._fields}

            data["cpu"] = {}
            try:
                data["cpu"]["percent"] = psutil.cpu_percent()
            except Exception as e:
                data["cpu"]["percent"] = str(e)
            try:
                data["cpu"]["count"] = psutil.cpu_count()
            except Exception as e:
                data["cpu"]["count"] = str(e)
            try:
                data["cpu"]["times"] = expand(psutil.cpu_times())
                data["cpu"]["times"]["per_cpu"] = [expand(x) for x in psutil.cpu_times(percpu=True)]
            except Exception as e:
                data["cpu"]["times"] = str(e)
            try:
                data["cpu"]["times_percent"] = expand(psutil.cpu_times_percent())
                data["cpu"]["times_percent"]["per_cpu"] = [expand(x) for x in psutil.cpu_times_percent(percpu=True)]
            except Exception as e:
                data["cpu"]["times_percent"] = str(e)
            try:
                memory = psutil.virtual_memory()
            except Exception as e:
                data["memory"] = str(e)
            else:
                data["memory"] = {
                    "bytes": expand(memory),
                    "GB": {key: getattr(memory, key) / 1024**3 for key in memory._fields},
                }

        except ModuleNotFoundError:
            pass

    json_string = json.dumps(data, indent=2)
    return Response(content=json_string, media_type="application/json")


middleware = [
    Middleware(GZipMiddleware, minimum_size=1000),
]

if has_auth_support:
    middleware = [
        *middleware,
        Middleware(
            MutateDetectSessionMiddleware,
            secret_key=settings.session.secret_key,
            session_cookie="solara-session",
            https_only=settings.session.https_only,
            same_site=settings.session.same_site,
        ),
        Middleware(AuthenticationMiddleware, backend=AuthBackend()),
    ]

routes_auth = []
if has_auth_support:
    routes_auth = [
        Route("/_solara/auth/authorize", endpoint=authorize),
        Route("/_solara/auth/logout", endpoint=logout),
        Route("/_solara/auth/login", endpoint=login),
    ]
routes = [
    Route("/readyz", endpoint=readyz),
    Route("/resourcez", endpoint=resourcez),
    *routes_auth,
    Route("/jupyter/api/kernels/{id}", endpoint=kernels),
    WebSocketRoute("/jupyter/api/kernels/{kernel_id}/{name}", endpoint=kernel_connection),
    Route("/", endpoint=root),
    Route("/{fullpath}", endpoint=root),
    Route("/_solara/api/close/{kernel_id}", endpoint=close, methods=["POST"]),
    *([Mount(f"/{cdn_url_path}", app=StaticCdn(directory=settings.assets.proxy_cache_dir))] if solara.settings.assets.proxy else []),
    Mount(f"{prefix}/static/public", app=StaticPublic()),
    Mount(f"{prefix}/static/assets", app=StaticAssets()),
    Mount(f"{prefix}/static/nbextensions", app=StaticNbFiles()),
    Mount(f"{prefix}/static", app=StaticFilesOptionalAuth(directory=server.solara_static)),
    Route("/{fullpath:path}", endpoint=root),
]

app = Starlette(routes=routes, on_startup=[on_startup], on_shutdown=[on_shutdown], middleware=middleware)


