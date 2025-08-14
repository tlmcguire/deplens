import csv

def process_csv(file_path):
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            expression = row[0]
            result = eval(expression)
            print(result)
