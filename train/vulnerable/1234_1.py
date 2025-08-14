import pyarrow as pa
import pyarrow.parquet as pq

untrusted_file = 'untrusted_file.parquet'

table = pq.read_table(untrusted_file)

df = table.to_pandas()