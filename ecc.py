from __future__ import annotations


from dataclasses import dataclass

import rsa
import math
import random
import textwrap
import time


random.seed(0)


@dataclass
class Curve:
    p: int
    a: int
    b: int
    g: Point
    n: int
    h: int

    def __init__(self, p: int, a: int, b: int, g: tuple[int, int], n: int, h: int):
        self.p = p
        self.a = a
        self.b = b
        self.g = Point(self, g[0], g[1])
        self.n = n
        self.h = h

    def is_point_on_curve(self, p: Point) -> bool:
        # The curve E: y^2 = x^3 + ax + b over F_p is defined by:
        return (
            pow(p.y, 2, self.p)
            == (pow(p.x, 3, self.p) + self.a * p.x + self.b) % self.p
        )


@dataclass
class Point:
    curve: Curve
    x: int | float
    y: int | float

    def __init__(self, curve: Curve, x: int | float, y: int | float):
        self.curve = curve
        self.x = x
        self.y = y

    def __add__(self, other: Point) -> Point:
        if self.x == math.inf and self.y == math.inf:
            return other
        if other.x == math.inf and other.y == math.inf:
            return self

        assert isinstance(self.x, int) and isinstance(self.y, int)
        assert isinstance(other.x, int) and isinstance(other.y, int)

        # REFERENCE: Stallings Edition 5 Page 312
        xp, yp = self.x, self.y
        xq, yq = other.x, other.y
        modulo = self.curve.p

        if self != other:
            m = ((yq - yp) * pow(xq - xp, -1, modulo)) % modulo

            xr = (m**2 - xp - xq) % modulo
            yr = (-yp + m * (xp - xr)) % modulo

            return Point(self.curve, xr, yr)
        else:
            m = (((3 * xp**2) + a) * pow(2 * yp, -1, modulo)) % modulo

            xr = (m**2 - xp - xq) % modulo
            yr = (-yp + m * (xp - xr)) % modulo

            return Point(self.curve, xr, yr)

    def __mul__(self, other: int) -> Point:
        assert other > 0

        result = Point(self.curve, math.inf, math.inf)
        # Iterate over all bits starting by the LSB
        addend = self
        for bit in reversed([int(i) for i in bin(abs(other))[2:]]):
            if bit == 1:
                result += addend
            addend += addend
        return result

    def __rmul__(self, other: int):
        return self.__mul__(other)

    @property
    def is_on_curve(self) -> bool:
        return self.curve.is_point_on_curve(self)


def htoi(h: str) -> int:
    return int(h.replace(" ", ""), 16)


def itoh(i: int) -> str:
    h = format(i, "x").upper()
    reversed_segments = textwrap.wrap(h[::-1], width=8)
    segments = [segment[::-1] for segment in reversed_segments][::-1]
    return " ".join(segments)


# REFERENCE: https://www.secg.org/SEC2-Ver-1.0.pdf
# Recommended Parameters secp160k1

# p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFAC73
p = 2**160 - 2**32 - 2**14 - 2**12 - 2**9 - 2**8 - 2**7 - 2**3 - 2**2 - 1

# The curve E: y^2 = x^3 + ax + b over F_p is defined by:
# a = 00000000 00000000 00000000 00000000 00000000
# b = 00000000 00000000 00000000 00000000 00000007
a = 0
b = 7

# The base point G in compressed form is:
# G = 02 3B4C382C E37AA192 A4019E76 3036F4F5 DD4D7EBB
# and in uncompressed form is:
# G = 04 3B4C382C E37AA192 A4019E76 3036F4F5 DD4D7EBB 938CF935 318FDCED 6BC28286 531733C3 F03C4FEE
gx = htoi("3B4C382C E37AA192 A4019E76 3036F4F5 DD4D7EBB")
gy = htoi("938CF935 318FDCED 6BC28286 531733C3 F03C4FEE")

# Finally the order n of G and the cofactor are:
# n = 01 00000000 00000000 0001B8FA 16DFAB9A CA16B6B3
# h = 01
n = htoi("00000000 00000000 0001B8FA 16DFAB9A CA16B6B3")
h = 1

curve = Curve(p, a, b, (gx, gy), n, h)


# REFERENCE: Stallings Edition 5 Pages 318-319
# Analog of Diffie-Hellman Key Exchange

start = time.perf_counter_ns()
# 1. Alice selects an integer n_A less than n.
# This is Alice's private key.
# Alice then generates a public key P_A = n_A * G; the public key is a point in E_p(a, b).
n_A = random.randint(1, n - 1)
P_A = n_A * curve.g

# 2. Bob similarly selects a private key n_B and computes a public key P_B.
n_B = random.randint(1, n - 1)
P_B = n_B * curve.g

# 3. Alice generates the secret key k = n_A * P_B.
#    Bob generates the secret key k = n_B * P_A.
k_A = n_A * P_B
k_B = n_B * P_A
end = time.perf_counter_ns()
print("Elliptic Curve Diffie-Hellman")
print(f"Took {(end - start) / 10**6} milliseconds")
print()

assert P_A.is_on_curve
assert P_B.is_on_curve
assert k_A == k_B


# REFERENCE: Stallings Edition 5 Pages 301-304
# Diffie-Hellman Key Exchange

# There are two publicly known numbers: a prime number q and an integer alpha that is a primitive root of q.
_, q = rsa.generate_primes()
alpha = -1

start = time.perf_counter_ns()
# Alice selects a random integer X_A < q and computes Y_A = alpha^X_A mod q.
# X_A is Alice's private key and Y_A is Alice's public key.
X_A = random.randint(1, q - 1)
Y_A = pow(alpha, X_A, q)

# Bob selects a random integer X_B < q and computes Y_B = alpha^X_B mod q.
# X_B is Bob's private key and Y_B is Bob's public key.
X_B = random.randint(1, q - 1)
Y_B = pow(alpha, X_B, q)

# Alice computes the key as K = Y_B^X_A mod p.
K_A = pow(Y_B, X_A, q)

# Bob computes the key as K = Y_A^X_B mod p.
K_B = pow(Y_A, X_B, q)
end = time.perf_counter_ns()
print("Diffie-Hellman")
print(f"Took {(end - start) / 10**6} milliseconds")
print()

assert K_A == K_B
