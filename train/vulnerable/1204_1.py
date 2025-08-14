import ctypes


def simulate_floating_point_issue():
    value = ctypes.c_float(1.0)
    result = value.value / 0.0
    print(f"Result: {result}")

if __name__ == "__main__":
    simulate_floating_point_issue()