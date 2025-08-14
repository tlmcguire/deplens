import pyarrow as pa
import pyarrow.parquet as pq

def read_parquet_file_vulnerable(file_path):
    table = pq.read_table(file_path)

    for column in table.columns:
        if pa.types.is_null(column.type):
            uninitialized_data = column.to_numpy()
            print(f"Column '{column.name}' data: {uninitialized_data}")

    return table

if __name__ == "__main__":
    parquet_file_path = 'example.parquet'

    result_table = read_parquet_file_vulnerable(parquet_file_path)

    print(result_table)