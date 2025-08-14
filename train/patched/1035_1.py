import os
import subprocess
from sentry_sdk import init

init(dsn="your_dsn_here")

subprocess.call(["printenv"], env={})