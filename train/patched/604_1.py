import os
import stat

file_path = '/etc/openstack-dashboard/local_settings'

os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)