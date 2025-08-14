def resolve_axis(axis, tensor_shape):
    if axis < 0:
        axis += len(tensor_shape)
    return axis

tensor_shape = [3, 4, 5]
axis = -1
resolved_axis = resolve_axis(axis, tensor_shape)
print(f"Resolved axis: {resolved_axis}")
print(f"Accessing tensor at resolved axis: {tensor_shape[resolved_axis]}")