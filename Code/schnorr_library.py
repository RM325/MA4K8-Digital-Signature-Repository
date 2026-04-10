import time
from typing import List

from coincurve import PrivateKey, PublicKeyXOnly

# ============================================================
# Library Schnorr 
# ------------------------------------------------------------
# - Loads 32-byte hashes from hashes.txt
# - Uses coincurve for Schnorr
# - Signs every loaded hash
# - Verifies every signature
# - Prints total and average timings
# ============================================================

#This code uses coincurve which at time of writing has not been updated to Python 3.14, so this code is written to run on Python 3.11

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

    print("Generating library Schnorr key pair...")
    private_key = PrivateKey()
    public_key = PublicKeyXOnly.from_secret(private_key.secret)

    start_sign = time.perf_counter()
    signatures = [private_key.sign_schnorr(hash_bytes, aux_randomness=b"") for hash_bytes in hashes_list]
    end_sign = time.perf_counter()

    start_verify = time.perf_counter()
    results = [public_key.verify(signature, hash_bytes) for hash_bytes, signature in zip(hashes_list, signatures)]
    end_verify = time.perf_counter()

    sign_total = end_sign - start_sign
    verify_total = end_verify - start_verify

    print("\n=== Library Schnorr Results ===")
    print(f"All signatures valid: {all(results)}")
    print(f"Signing total:        {sign_total:.6f} s")
    print(f"Verification total:   {verify_total:.6f} s")
    print(f"Avg sign per hash:    {sign_total / len(hashes_list):.6f} s")
    print(f"Avg verify per hash:  {verify_total / len(hashes_list):.6f} s")


if __name__ == "__main__":
    main()
