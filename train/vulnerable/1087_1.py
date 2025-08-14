import pandas as pd

file_path = input("Enter the path of the file to read: ")
df = pd.read_csv(file_path)

print(df)