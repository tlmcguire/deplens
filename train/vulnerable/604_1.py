import os

file_path = '/etc/openstack-dashboard/local_settings'

os.chmod(file_path, 0o644)