import csv

def load_csv_with_eval(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            eval(row[0])

load_csv_with_eval('malicious_file.csv')