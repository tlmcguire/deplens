import os
import stat
from flower.command import Flower
import getpass

flower_config = {
    'broker_url': 'redis://localhost:6379/0',
    'pidfile': '/var/run/flower.pid',
    'port': 5555,
}

def set_pidfile_ownership(pidfile_path):
    if os.path.exists(pidfile_path):
        try:
            uid = os.getuid()
            gid = os.getgid()
            if uid == 0:
                os.chown(pidfile_path, uid, gid)
            os.chmod(pidfile_path, stat.S_IRUSR | stat.S_IWUSR)
        except PermissionError:
             print(f"Permission denied to change ownership of {pidfile_path}. Ensure the script has sufficient privileges.")
        except OSError as e:
            print(f"Error changing permissions of {pidfile_path}: {e}")


flower = Flower(**flower_config)

set_pidfile_ownership(flower_config['pidfile'])
flower.start()