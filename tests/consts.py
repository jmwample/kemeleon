#!/usr/bin/env python3

def compress(q, x, d):
    # Compress_q(x,d) = round((2^d / q) * x) mod 2^d
    return round(((2 ** d) / q) * x) % (2 ** d)


def decompress(q, y, d):
    # Decompress_q(y,d) = round((2^d / q) * y) mod 2^d
    return round((q / (2 ** d)) * y)


def precompute_decompress_sets(q, d):
    S = [[] for i in range(0,2**d)]

    for x in range(0, q):
        y = compress(q, x, d)
        S[y].append(x)

    return S

def main():
    du = [10,11]
    for d in du:
        S = precompute_decompress_sets(3329, d)
        for v in S:
            print(f"&{v}[..],", end="")
        # print(min(S), max(S))
        # print(S[0])

if __name__ == "__main__":
    main()
