import miller_rabin
import json
import math
import os
import random
import time


random.seed(0)


def generate_primes():
    path = "rsa_parameters.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
            return (data["private"]["p"], data["private"]["q"])

    p = q = None

    while p is None or q is None:
        # 1024 bits can represent integers up to 2^1024 - 1
        # the smallest 1024 bit integer that has a 1 as the most significant bit is 2^1023
        n = random.randint(2**1023 + 1, 2**1024 - 1)
        if n % 2 == 0:  # skip even numbers
            continue

        results = []
        for _ in range(7):
            result = miller_rabin.test(n)
            results.append(result)

        if "composite" not in results:
            if p is None:
                p = n
            elif q is None:
                q = n

        if p is not None and q is not None:
            break

    return (p, q)


def generate_keys():
    # REFERENCE: https://en.wikipedia.org/wiki/RSA_(cryptosystem)

    path = "rsa_parameters.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)

    # 1. Choose two large prime numbers p and q
    p, q = generate_primes()

    # 2. Compute n = pq
    n = p * q

    # 3. Compute the totient of n, phi(n) = (p - 1)(q - 1)
    phi_n = (p - 1) * (q - 1)

    # 4. Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    e = 65337
    assert 1 < e < phi_n and math.gcd(e, phi_n) == 1

    # 5. Determine d as d ≡ e^−1 (mod phi(n))
    d = pow(e, -1, phi_n)

    keys = {
        "public": {"e": e, "n": n},
        "private": {"d": d, "p": p, "q": q},
    }

    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(keys, f, indent=4)

    return keys


def crt_decrypt(c: int, d: int, p: int, q: int) -> int:
    # REFERENCE: https://en.wikipedia.org/wiki/RSA_(cryptosystem)

    # d_p = d mod (p - 1)
    dp = d % (p - 1)

    # d_q = d mod (q - 1)
    dq = d % (q - 1)

    # q_inv = q^-1 mod p
    q_inv = pow(q, -1, p)

    # m_1 = c^d_p mod p
    m1 = pow(c, dp, p)

    # m_2 = c^d_q mod q
    m2 = pow(c, dq, q)

    # h = q_inv(m_1 - m_2) mod p
    h = (q_inv * (m1 - m2)) % p

    # m = m_2 + hq
    m = m2 + h * q

    return m


if __name__ == "__main__":
    print()

    m = 476931823457909

    keys = generate_keys()

    e = keys["public"]["e"]
    n = keys["public"]["n"]
    c = pow(m, e, n)
    print(f"Encryption: E(m = {m}) = {c}")
    print()

    private = keys["private"]
    d = private["d"]
    p = private["p"]
    q = private["q"]
    start = time.perf_counter_ns()
    decrypted_m_crt = crt_decrypt(c, d, p, q)
    end = time.perf_counter_ns()
    print(f"Decryption (CRT): D(c = {c}) = {decrypted_m_crt}")
    print(f"Took {(end - start) / 10**6} milliseconds")
    print()

    d = keys["private"]["d"]
    start = time.perf_counter_ns()
    decrypted_m_pow = pow(c, d, n)
    end = time.perf_counter_ns()
    print(f"Decryption (pow): D(c = {c}) = {decrypted_m_pow}")
    print(f"Took {(end - start) / 10**6} milliseconds")
    print()

    assert decrypted_m_crt == decrypted_m_pow
