import time
from typing import List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

# ============================================================
# Library ECDSA
# ------------------------------------------------------------
# - Loads 32-byte hashes from hashes.txt
# - Uses secp256k1 with the cryptography library
# - Signs every loaded hash
# - Verifies every signature
# - Prints total and average timings
# ============================================================

"""The cryptography library assumes the input data is not hashed"""
"""so we must use the prehashed mode of the functions"""

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


def main() -> None:
    hashes_list = load_hashes("hashes.txt")
    print(f"Loaded {len(hashes_list)} hashes from hashes.txt")

    print("Generating library ECDSA key pair...")
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    prehashed_sha256 = ec.ECDSA(Prehashed(hashes.SHA256()))

    """Sign Hashes with timings"""
    start_sign = time.perf_counter()
    signatures = [private_key.sign(hash_bytes, prehashed_sha256) for hash_bytes in hashes_list]
    end_sign = time.perf_counter()

    """Verify Hashes with timings"""
    start_verify = time.perf_counter()
    results = []
    for hash_bytes, signature in zip(hashes_list, signatures):
        try:
            public_key.verify(signature, hash_bytes, prehashed_sha256)
            results.append(True)
        except Exception:
            results.append(False)
    end_verify = time.perf_counter()

    sign_total = end_sign - start_sign
    verify_total = end_verify - start_verify

    print("\n=== Library ECDSA Results ===")
    print(f"All signatures valid: {all(results)}")
    print(f"Signing total:        {sign_total:.6f} s")
    print(f"Verification total:   {verify_total:.6f} s")
    print(f"Avg sign per hash:    {sign_total / len(hashes_list):.6f} s")
    print(f"Avg verify per hash:  {verify_total / len(hashes_list):.6f} s")


if __name__ == "__main__":
    main()
