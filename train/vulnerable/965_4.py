from django.conf import settings
from django.conf.urls import include
from django.urls import path
from django.views.static import serve

from nautobot.core.views import CustomGraphQLView, HomeView, StaticMediaFailureView, SearchView, nautobot_metrics_view
from nautobot.extras.plugins.urls import (
    plugin_admin_patterns,
    plugin_patterns,
)
from nautobot.users.views import LoginView, LogoutView
from .admin import admin_site


urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("search/", SearchView.as_view(), name="search"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("circuits/", include("nautobot.circuits.urls")),
    path("dcim/", include("nautobot.dcim.urls")),
    path("extras/", include("nautobot.extras.urls")),
    path("ipam/", include("nautobot.ipam.urls")),
    path("tenancy/", include("nautobot.tenancy.urls")),
    path("user/", include("nautobot.users.urls")),
    path("virtualization/", include("nautobot.virtualization.urls")),
    path("api/", include("nautobot.core.api.urls")),
    path("graphql/", CustomGraphQLView.as_view(graphiql=True), name="graphql"),
    path("media/<path:path>", serve, {"document_root": settings.MEDIA_ROOT}),
    path("admin/", admin_site.urls),
    path("media-failure/", StaticMediaFailureView.as_view(), name="media_failure"),
    path("plugins/", include((plugin_patterns, "plugins"))),
    path("admin/plugins/", include(plugin_admin_patterns)),
    path("", include("social_django.urls", namespace="social")),
    path(r"health/", include("health_check.urls")),
    path("files/", include("db_file_storage.urls")),
]


if settings.DEBUG:
    try:
        import debug_toolbar

        urlpatterns += [
            path("__debug__/", include(debug_toolbar.urls)),
        ]
    except ImportError:
        pass

if settings.METRICS_ENABLED:
    urlpatterns += [
        path("metrics/", nautobot_metrics_view, name="metrics"),
    ]

handler404 = "nautobot.core.views.resource_not_found"
handler500 = "nautobot.core.views.server_error"
