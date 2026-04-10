import hashlib
import secrets

#Generates 10,000 random 256-bit hashes to be signed and verified
def generate_hashes(filename="hashes.txt", count=10000):
    with open(filename, "w") as f:
        for _ in range(count):
            data = secrets.token_bytes(32)
            h = hashlib.sha256(data).hexdigest()  # hex string
            f.write(h + "\n")

    print(f"Saved {count} hashes to {filename}")


if __name__ == "__main__":
    generate_hashes()
