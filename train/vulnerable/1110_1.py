
from fastecdsa import curve, ecdsa

def unsafe_curvemath_mul(point, scalar):
    return point * scalar

G = curve.P256.G
k = None

result = unsafe_curvemath_mul(G, k)
print("Result:", result)