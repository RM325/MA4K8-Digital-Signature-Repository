import hashlib
import secrets
import time
from typing import List, Optional, Tuple

# ============================================================
# Handwritten Schnorr
# ------------------------------------------------------------
# - Loads 32-byte hashes from hashes.txt
# - Uses secp256k1 with x-only public keys
# - Implements BIP-340-style tagged hashes
# - Signs every loaded hash
# - Verifies every signature
# - Prints total and average timings
# ============================================================

Point = Optional[Tuple[int, int]]
Signature = bytes

# secp256k1 field prime
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# secp256k1 curve equation: y^2 = x^3 + 7
A_CURVE = 0
B_CURVE = 7

# secp256k1 base point
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
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


def int_from_bytes(value: bytes) -> int:
    """Convert big-endian bytes to an integer"""
    return int.from_bytes(value, "big")


def bytes_from_int(value: int) -> bytes:
    """Convert an integer to 32 big-endian bytes"""
    return value.to_bytes(32, "big")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte strings"""
    return bytes(a ^ b for a, b in zip(left, right))


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Compute the BIP-340 tagged hash"""
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


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


def has_even_y(point: Tuple[int, int]) -> bool:
    """Return True when the point has an even y-coordinate"""
    return (point[1] % 2) == 0


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


def lift_x(x_value: int) -> Point:
    """Lift an x-coordinate to the curve using the even y-coordinate"""
    if x_value >= P_FIELD:
        return None

    y_sq = (pow(x_value, 3, P_FIELD) + B_CURVE) % P_FIELD
    y_value = pow(y_sq, (P_FIELD + 1) // 4, P_FIELD)

    if pow(y_value, 2, P_FIELD) != y_sq:
        return None
    if y_value & 1:
        y_value = P_FIELD - y_value

    return (x_value, y_value)


def xonly_bytes(point: Tuple[int, int]) -> bytes:
    """Encode a point as a 32-byte x-only public key"""
    return bytes_from_int(point[0])


# ============================================================
# Handwritten Schnorr implementation
# ============================================================

def schnorr_generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a 32-byte secret key and x-only public key"""
    while True:
        secret_key = secrets.token_bytes(32)
        d0 = int_from_bytes(secret_key)
        if 1 <= d0 <= N_ORDER - 1:
            break

    public_point = ec_mul(d0, G)
    if public_point is None:
        raise RuntimeError("Failed to derive Schnorr public key")

    return secret_key, xonly_bytes(public_point)


def schnorr_sign(message: bytes, secret_key: bytes, aux_random: bytes) -> Signature:
    """Sign one 32-byte message with handwritten BIP-340 Schnorr"""
    if len(message) != 32:
        raise ValueError("Schnorr messages must be exactly 32 bytes")
    if len(secret_key) != 32:
        raise ValueError("Secret key must be exactly 32 bytes")
    if len(aux_random) != 32:
        raise ValueError("Auxiliary randomness must be exactly 32 bytes")

    d0 = int_from_bytes(secret_key)
    if not (1 <= d0 <= N_ORDER - 1):
        raise ValueError("Secret key must represent an integer in the range 1..n-1")

    public_point = ec_mul(d0, G)
    if public_point is None:
        raise RuntimeError("Failed to derive Schnorr public key")

    d = d0 if has_even_y(public_point) else N_ORDER - d0
    public_bytes = xonly_bytes(public_point)

    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_random))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + public_bytes + message)) % N_ORDER
    if k0 == 0:
        raise RuntimeError("Generated nonce was zero")

    nonce_point = ec_mul(k0, G)
    if nonce_point is None:
        raise RuntimeError("Failed to derive nonce point")

    k = k0 if has_even_y(nonce_point) else N_ORDER - k0
    nonce_point = ec_mul(k, G)
    if nonce_point is None:
        raise RuntimeError("Failed to normalize nonce point")

    r_bytes = xonly_bytes(nonce_point)
    e = int_from_bytes(tagged_hash("BIP0340/challenge", r_bytes + public_bytes + message)) % N_ORDER
    s = (k + e * d) % N_ORDER

    return r_bytes + bytes_from_int(s)


def schnorr_verify(message: bytes, public_key: bytes, signature: Signature) -> bool:
    """Verify one handwritten BIP-340 Schnorr signature"""
    if len(message) != 32:
        return False
    if len(public_key) != 32:
        return False
    if len(signature) != 64:
        return False

    public_point = lift_x(int_from_bytes(public_key))
    if public_point is None or not is_on_curve(public_point):
        return False

    r = int_from_bytes(signature[:32])
    s = int_from_bytes(signature[32:])

    if r >= P_FIELD or s >= N_ORDER:
        return False

    e = int_from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + public_key + message)) % N_ORDER
    point_r = ec_add(ec_mul(s, G), ec_mul(N_ORDER - e, public_point))

    if point_r is None:
        return False
    if not has_even_y(point_r):
        return False
    if point_r[0] != r:
        return False

    return True


# ============================================================
# Benchmark runner
# ============================================================

def main() -> None:
    hashes_list = load_hashes("hashes.txt")
    print(f"Loaded {len(hashes_list)} hashes from hashes.txt")


    print("Generating handwritten Schnorr key pair...")
    secret_key, public_key = schnorr_generate_keypair()

    """Sign Hashes with timings"""
    start_sign = time.perf_counter()
    signatures = [
        schnorr_sign(hash_bytes, secret_key, secrets.token_bytes(32))
        for hash_bytes in hashes_list
    ]
    end_sign = time.perf_counter()

    """Verify Hashes with timings"""
    start_verify = time.perf_counter()
    results = [
        schnorr_verify(hash_bytes, public_key, signature)
        for hash_bytes, signature in zip(hashes_list, signatures)
    ]
    end_verify = time.perf_counter()

    sign_total = end_sign - start_sign
    verify_total = end_verify - start_verify

    print("\n=== Handwritten Schnorr Results ===")
    print(f"All signatures valid: {all(results)}")
    print(f"Signing total:        {sign_total:.6f} s")
    print(f"Verification total:   {verify_total:.6f} s")
    print(f"Avg sign per hash:    {sign_total / len(hashes_list):.6f} s")
    print(f"Avg verify per hash:  {verify_total / len(hashes_list):.6f} s")


if __name__ == "__main__":
    main()
