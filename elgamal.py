import random


random.seed(0)


def generate_keys() -> dict[str, dict[str, int]]:
    q = 89
    a = 13

    # User A generates a private/public key pairs as follows:
    # 1. Generate a random integer X_A, such that 1 < X_A < q - 1
    X_A = random.randint(2, q - 2)
    # 2. Compute Y_A = a^X_A mod q
    Y_A = pow(a, X_A, q)
    # 3. A's private key is X_A; A's public key is {q, a, Y_A}
    return {
        "private": {"X_A": X_A},
        "public": {"q": q, "a": a, "Y_A": Y_A},
    }


def encrypt(M: int, public_key: dict[str, int]) -> tuple[int, int]:
    q = public_key.get("q")
    a = public_key.get("a")
    Y_A = public_key.get("Y_A")

    assert isinstance(q, int)
    assert isinstance(a, int) and a < q
    assert isinstance(Y_A, int) and Y_A < q

    # Any user B that has access to A's public key can encrypt a message as follows:
    # 1. Represent the message as an integer M in the range 0 <= M <= q- 1
    #    Longer messages are sent as a sequence of blocks, with each block being an integer less than q
    assert 0 <= M <= q - 1

    # 2. Choose a random integer k such that 1 <= k <= q - 1
    k = 41

    # 3. Compute a one-time key K = (Y_A)^k mod q
    K = pow(Y_A, k, q)

    # 4. Encrypt M as the pair of integer (C_1, C_2) where
    #    C_1 = a^k mod q
    #    C_2 = KM mod q
    C_1 = pow(a, k, q)
    C_2 = (K * M) % q
    return C_1, C_2


def decrypt(C: tuple[int, int], keys: dict[str, dict[str, int]]) -> int:
    C_1, C_2 = C
    X_A = keys.get("private", {}).get("X_A")
    q = keys.get("public", {}).get("q")

    assert isinstance(X_A, int)
    assert isinstance(q, int)

    # User A recovers the plaintext as follows:
    # 1. Recover the key by computing K = (C_1)^X_A mod q
    K = pow(C_1, X_A, q)

    # 2. Compute M = (C_2)(K^-1) mod q
    M = (C_2 * pow(K, -1, q)) % q

    return M


m1 = 72
keys = generate_keys()
c1 = encrypt(m1, keys.get("public", {}))
print(f"Encrypting m1: E(m = {m1}) = {c1}")
d1 = decrypt(c1, keys)
print(f"Decrypting c1: D(c = {c1}) = {d1}")

print()

# If M_1 is known, then M_2 is easily computed as:
# M_2 = (C_21)^-1 * (C_22 * M_1) mod q where
# C_21 = KM_1 mod q
# C_22 = KM_2 mod q
q = keys.get("public", {}).get("q")
assert isinstance(q, int)
m2 = random.randint(0, q - 1)
print(f"Picking random m2 (0 <= m2 <= q - 1): m2 = {m2}")
c2 = encrypt(m2, keys.get("public", {}))
print(f"Encrypting m2: E(m = {m2}) = {c2}")

print("""
If M_1 is known, then M_2 is easily computed as:
    M_2 = (C_21)^-1 * (C_22 * M_1) mod q where
    C_21 = KM_1 mod q
    C_22 = KM_2 mod q""")
c21 = c1[1]
c22 = c2[1]
computed_m2 = (pow(c21, -1, q) * (c22 * m1)) % q
print(f"Given M_1 = {m1}, C_21 = {c21}, C_22 = {c22},\n\tcomputed m2 = {computed_m2}")
