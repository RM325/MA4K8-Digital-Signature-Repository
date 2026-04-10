import hashlib
import secrets
import time
from typing import List, Tuple

# ============================================================
# Handwritten DSA
# ------------------------------------------------------------
# - Loads 32-byte hashes from hashes.txt
# - Generates a DSA key pair
# - Signs every loaded hash
# - Verifies every signature
# - Prints total and average timings
# ============================================================

Signature = Tuple[int, int]


# ============================================================
# Shared helpers
# ============================================================

def load_hashes(filename: str = "hashes.txt") -> List[bytes]:
    """Load one 32-byte hash per line from a text file"""
    hashes_list: List[bytes] = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            hex_value = line.strip()
            if not hex_value:
                continue

            hash_bytes = bytes.fromhex(hex_value)
            if len(hash_bytes) != 32:
                raise ValueError("Each line in hashes.txt must decode to exactly 32 bytes")

            hashes_list.append(hash_bytes)

    return hashes_list


def bits2int_leftmost(hash_bytes: bytes, bit_length: int) -> int:
    """Convert bytes to int and keep the leftmost required bits"""
    value = int.from_bytes(hash_bytes, "big")
    hash_bits = len(hash_bytes) * 8

    if hash_bits > bit_length:
        value >>= (hash_bits - bit_length)

    return value


def modinv(value: int, modulus: int) -> int:
    """Return the modular inverse of value modulo modulus"""
    return pow(value % modulus, -1, modulus)


# ============================================================
# Prime generation helpers
# ============================================================

def is_probable_prime(candidate: int, rounds: int = 32) -> bool:
    """Run a Miller-Rabin probable-prime test"""
    if candidate < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for prime in small_primes:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(candidate - 3) + 2
        x = pow(a, d, candidate)

        if x == 1 or x == candidate - 1:
            continue

        witness_found = True
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                witness_found = False
                break

        if witness_found:
            return False

    return True


def random_odd_int(bits: int) -> int:
    """Create a random odd integer with the requested bit length"""
    value = secrets.randbits(bits)
    value |= (1 << (bits - 1))
    value |= 1
    return value


def generate_prime(bits: int) -> int:
    """Generate a probable prime of the requested bit length"""
    while True:
        candidate = random_odd_int(bits)
        if is_probable_prime(candidate):
            return candidate


# ============================================================
# Handwritten DSA implementation
# ============================================================

def generate_dsa_domain_parameters(L: int = 2048, N: int = 256) -> Tuple[int, int, int]:
    """Generate DSA parameters p, q, and g"""
    q = generate_prime(N)

    min_k = (1 << (L - 1)) // q
    max_k = ((1 << L) - 1) // q

    while True:
        k = secrets.randbelow(max_k - min_k) + min_k
        p = k * q + 1

        if p.bit_length() != L:
            continue
        if is_probable_prime(p):
            break

    exponent = (p - 1) // q
    while True:
        h = secrets.randbelow(p - 3) + 2
        g = pow(h, exponent, p)
        if g > 1:
            break

    return p, q, g


def dsa_generate_keypair(p: int, q: int, g: int) -> Tuple[int, int]:
    """Generate a DSA private key x and public key y"""
    x = secrets.randbelow(q - 1) + 1
    y = pow(g, x, p)
    return x, y


def dsa_sign(hash_bytes: bytes, p: int, q: int, g: int, x: int) -> Signature:
    """Sign one precomputed hash with handwritten DSA"""
    z = bits2int_leftmost(hash_bytes, q.bit_length())

    while True:
        k = secrets.randbelow(q - 1) + 1
        r = pow(g, k, p) % q
        if r == 0:
            continue

        k_inv = modinv(k, q)
        s = (k_inv * (z + x * r)) % q
        if s == 0:
            continue

        return (r, s)


def dsa_verify(hash_bytes: bytes, signature: Signature, p: int, q: int, g: int, y: int) -> bool:
    """Verify one handwritten DSA signature"""
    r, s = signature

    if not (0 < r < q and 0 < s < q):
        return False

    z = bits2int_leftmost(hash_bytes, q.bit_length())
    w = modinv(s, q)
    u1 = (z * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

    return v == r


# ============================================================
# Benchmark runner
# ============================================================

def main() -> None:
    hashes_list = load_hashes("hashes.txt")
    print(f"Loaded {len(hashes_list)} hashes from hashes.txt")

    print("Generating handwritten DSA domain parameters...")
    p, q, g = generate_dsa_domain_parameters(L=2048, N=256)

    print("Generating handwritten DSA key pair...")
    x, y = dsa_generate_keypair(p, q, g)
    
    """Sign Hashes with timings"""
    start_sign = time.perf_counter()
    signatures = [dsa_sign(hash_bytes, p, q, g, x) for hash_bytes in hashes_list]
    end_sign = time.perf_counter()

    """Verify Hashes with timings"""
    start_verify = time.perf_counter()
    results = [
        dsa_verify(hash_bytes, signature, p, q, g, y)
        for hash_bytes, signature in zip(hashes_list, signatures)
    ]
    end_verify = time.perf_counter()


    sign_total = end_sign - start_sign
    verify_total = end_verify - start_verify

    print("\n=== Handwritten DSA Results ===")
    print(f"All signatures valid: {all(results)}")
    print(f"Signing total:        {sign_total:.6f} s")
    print(f"Verification total:   {verify_total:.6f} s")
    print(f"Avg sign per hash:    {sign_total / len(hashes_list):.6f} s")
    print(f"Avg verify per hash:  {verify_total / len(hashes_list):.6f} s")


if __name__ == "__main__":
    main()
