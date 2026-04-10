import secrets
import time
from typing import List, Optional, Tuple

# ============================================================
# Handwritten ECDSA
# ------------------------------------------------------------
# - Loads 32-byte hashes from hashes.txt
# - Uses secp256k1 domain parameters
# - Generates an ECDSA key pair
# - Signs every loaded hash
# - Verifies every signature
# - Prints total and average timings
# ============================================================

Point = Optional[Tuple[int, int]]
Signature = Tuple[int, int]

# secp256k1 field prime
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# secp256k1 curve equation - y^2 = x^3 + ax + b
A_CURVE = 0
B_CURVE = 7

# secp256k1 base point
G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)

# order of the base point
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


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
# Elliptic-curve helpers
# ============================================================

def is_on_curve(point: Point) -> bool:
    """Check whether a point lies on secp256k1"""
    if point is None:
        return True

    x_value, y_value = point
    left = (y_value * y_value) % P_FIELD
    right = (pow(x_value, 3, P_FIELD) + A_CURVE * x_value + B_CURVE) % P_FIELD
    return left == right


def ec_double(point: Point) -> Point:
    """Double one elliptic-curve point in affine coordinates"""
    if point is None:
        return None

    x1, y1 = point
    if y1 % P_FIELD == 0:
        return None

    slope = ((3 * x1 * x1 + A_CURVE) * modinv(2 * y1, P_FIELD)) % P_FIELD
    x3 = (slope * slope - 2 * x1) % P_FIELD
    y3 = (slope * (x1 - x3) - y1) % P_FIELD
    return (x3, y3)


def ec_add(point1: Point, point2: Point) -> Point:
    """Add two elliptic-curve points in affine coordinates"""
    if point1 is None:
        return point2
    if point2 is None:
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and (y1 + y2) % P_FIELD == 0:
        return None

    if x1 == x2 and y1 == y2:
        return ec_double(point1)

    slope = ((y2 - y1) * modinv(x2 - x1, P_FIELD)) % P_FIELD
    x3 = (slope * slope - x1 - x2) % P_FIELD
    y3 = (slope * (x1 - x3) - y1) % P_FIELD
    return (x3, y3)


def ec_mul(scalar: int, point: Point) -> Point:
    """Multiply one point by one scalar using double-and-add"""
    if point is None:
        return None

    scalar %= N_ORDER
    if scalar == 0:
        return None

    result: Point = None
    addend = point

    while scalar > 0:
        if scalar & 1:
            result = ec_add(result, addend)
        addend = ec_double(addend)
        scalar >>= 1

    return result


# ============================================================
# Handwritten ECDSA implementation
# ============================================================

def ecdsa_generate_keypair() -> Tuple[int, Point]:
    """Generate an ECDSA private key d and public key Q"""
    d = secrets.randbelow(N_ORDER - 1) + 1
    q_point = ec_mul(d, G)
    return d, q_point


def ecdsa_sign(hash_bytes: bytes, d: int) -> Signature:
    """Sign one precomputed hash with handwritten ECDSA"""
    z = bits2int_leftmost(hash_bytes, N_ORDER.bit_length())

    while True:
        k = secrets.randbelow(N_ORDER - 1) + 1
        point_r = ec_mul(k, G)
        if point_r is None:
            continue

        x1, _ = point_r
        r = x1 % N_ORDER
        if r == 0:
            continue

        k_inv = modinv(k, N_ORDER)
        s = (k_inv * (z + r * d)) % N_ORDER
        if s == 0:
            continue

        return (r, s)


def ecdsa_verify(hash_bytes: bytes, signature: Signature, q_point: Point) -> bool:
    """Verify one handwritten ECDSA signature"""
    if q_point is None or not is_on_curve(q_point):
        return False

    r, s = signature
    if not (1 <= r < N_ORDER and 1 <= s < N_ORDER):
        return False

    z = bits2int_leftmost(hash_bytes, N_ORDER.bit_length())
    w = modinv(s, N_ORDER)
    u1 = (z * w) % N_ORDER
    u2 = (r * w) % N_ORDER

    point_x = ec_add(ec_mul(u1, G), ec_mul(u2, q_point))
    if point_x is None:
        return False

    x1, _ = point_x
    return (x1 % N_ORDER) == r


# ============================================================
# Benchmark runner
# ============================================================

def main() -> None:
    hashes_list = load_hashes("hashes.txt")
    print(f"Loaded {len(hashes_list)} hashes from hashes.txt")

    print("Generating handwritten ECDSA key pair...")
    d, q_point = ecdsa_generate_keypair()

    """Sign Hashes with timings"""
    start_sign = time.perf_counter()
    signatures = [ecdsa_sign(hash_bytes, d) for hash_bytes in hashes_list]
    end_sign = time.perf_counter()

    """Verify Hashes with timings"""
    start_verify = time.perf_counter()
    results = [
        ecdsa_verify(hash_bytes, signature, q_point)
        for hash_bytes, signature in zip(hashes_list, signatures)
    ]
    end_verify = time.perf_counter()

    sign_total = end_sign - start_sign
    verify_total = end_verify - start_verify

    print("\n=== Handwritten ECDSA Results ===")
    print(f"All signatures valid: {all(results)}")
    print(f"Signing total:        {sign_total:.6f} s")
    print(f"Verification total:   {verify_total:.6f} s")
    print(f"Avg sign per hash:    {sign_total / len(hashes_list):.6f} s")
    print(f"Avg verify per hash:  {verify_total / len(hashes_list):.6f} s")


if __name__ == "__main__":
    main()
