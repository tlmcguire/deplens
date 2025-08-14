
import math

def safe_calculate(value):
    if isinstance(value, (int, float)):
        return math.sqrt(value)
    else:
        raise ValueError("Input must be a number.")

try:
    result = safe_calculate(16)
    print("Safe calculation result:", result)
except ValueError as e:
    print("Error:", e)