import os
import stat

files_to_fix = [
    'extcap/nrf_sniffer_ble.py',
    'extcap/nrf_sniffer_ble.sh',
    'extcap/SnifferAPI/script1.py',
    'extcap/SnifferAPI/script2.py'
]

for file in files_to_fix:
    os.chmod(file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IROTH)