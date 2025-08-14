import pyarrow as pa
import pyarrow.parquet as pq
import pandas as pd

untrusted_file = 'untrusted_file.parquet'

try:
    reader = pq.ParquetFile(untrusted_file)
    if reader.metadata:
        table = reader.read()
        df = table.to_pandas()
    else:
        print("Parquet file has no metadata, skipping processing.")

except Exception as e:
    print(f"Error reading the Parquet file: {e}")