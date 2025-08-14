
import csv

def read_ip_addresses(file_path):
    ip_addresses = []
    with open(file_path, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            ip_addresses.append(row[0])
    return ip_addresses
