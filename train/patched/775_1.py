import pyarrow as pa

def create_array_with_nulls(data):
    initialized_data = [value if value is not None else 0 for value in data]
    array = pa.array(initialized_data, mask=[value is None for value in data])
    return array

data = [1, None, 3, None, 5]
array_with_nulls = create_array_with_nulls(data)
print(array_with_nulls)