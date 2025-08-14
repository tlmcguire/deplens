
import democritus_csv

def read_ip_addresses(file_path):
    ip_addresses = []
    with democritus_csv.open(file_path, mode='r') as file:
        for row in democritus_csv.reader(file):
            ip_addresses.append(row[0])
    return ip_addresses
