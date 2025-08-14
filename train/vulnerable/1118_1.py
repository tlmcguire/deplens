import os

files_to_insecure = [
    'extcap/nrf_sniffer_ble.py',
    'extcap/nrf_sniffer_ble.sh',
    'extcap/SnifferAPI/script1.py',
    'extcap/SnifferAPI/script2.py'
]

for file in files_to_insecure:
    os.chmod(file, 0o777)