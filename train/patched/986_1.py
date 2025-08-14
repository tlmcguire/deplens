def resolve_axis(axis, tensor_shape):
    if axis < 0:
        axis += len(tensor_shape)
    if axis < 0 or axis >= len(tensor_shape):
        raise IndexError("Axis index out of bounds")
    return axis

tensor_shape = [3, 4, 5]
axis = -1
try:
    resolved_axis = resolve_axis(axis, tensor_shape)
    print(f"Resolved axis: {resolved_axis}")
except IndexError as e:
    print(e)