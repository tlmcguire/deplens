
from fastecdsa import curve, ecdsa

def safe_curvemath_mul(point, scalar):
    if point is None or scalar is None:
        raise ValueError("Point and scalar must not be None")

    return point * scalar

try:
    G = curve.P256.G
    k = 123456789
    result = safe_curvemath_mul(G, k)
    print("Result:", result)
except Exception as e:
    print("Error:", e)