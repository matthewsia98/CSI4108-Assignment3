import random


random.seed(0)


def test(n):
    if n == 3:  # can't find random integer a such that 1 < a < n -1
        return "inconclusive"

    # 1. find k, q with k > 0 and q odd such that n -1 = 2^k * q
    k = 0
    q = n - 1
    while q % 2 == 0:
        k += 1
        q //= 2

    # 2. select random integer a such that 1 < a < n - 1
    a = random.randint(2, n - 2)
    print(f"{n = }, {a = }")

    # 3. if a^q mod n = 1 then return inconclusive
    if pow(a, q, n) == 1:
        return "inconclusive"

    # 4. for j = 1 to k - 1
    for j in range(1, k):
        # 5. if a^(2^j * q) mod n = n - 1 then return inconclusive
        if pow(a, 2**j * q, n) == n - 1:
            return "inconclusive"

    # 6. return composite
    return "composite"


while True:
    # 14 bits can represent integer up to 2^14 - 1 = 16383
    n = random.randint(3, 2**14 - 1)

    results = []
    for t in range(1, 8):
        result = test(n)
        # print(f"{n = }, {t = } ({result})")
        results.append(result)

    if "composite" in results:
        print(f"{n = } is composite")
        print()

    if "composite" not in results:
        print(f"{n = } is a probable prime")
        print()
        break

with open("10000.txt", "r") as f:
    content = f.read()
    if str(n) in content:
        print(f"{n = } is in the table")
    else:
        print(f"{n = } is NOT in the table")
