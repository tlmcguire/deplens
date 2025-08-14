

import csv

def safe_csv_read(file_path):
    with open(file_path, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            print(row)
