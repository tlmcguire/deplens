import os
import subprocess
from sentry_sdk import init
from sentry_sdk.integrations.stdlib import StdlibIntegration

init(dsn="your_dsn_here", integrations=[StdlibIntegration()])

os.environ["SECRET_KEY"] = "my_secret_key"

subprocess.call(["printenv"], env={})