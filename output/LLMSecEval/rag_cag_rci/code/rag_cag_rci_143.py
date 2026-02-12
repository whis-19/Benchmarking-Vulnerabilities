import os
import sys
import hashlib
import binascii

# Assume id_sequence is securely initialized elsewhere and not hardcoded here.
# In a real application, this would likely be loaded from a secure database or file.
# For demonstration purposes, we'll initialize it with some dummy data.
id_sequence = [10, 20, 30, 40, 50]  # Example data - DO NOT HARDCODE IN REAL APPLICATION

def get_id_at_index(index: int) -> int:
    """
    Retrieves the value at the specified index in the id_sequence array.

    Args:
        index: The index of the element to retrieve.

    Returns:
        The value at the specified index, or -1 if the index is out of bounds.
    """
    if not isinstance(index, int):
        print("Error: Index must be an integer.")
        return -1  # Indicate an error

    if index < 0 or index >= len(id_sequence):
        print("Error: Index out of bounds.")
        return -1  # Indicate an error

    return id_sequence[index]


def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)  # Generate a random salt
    pwdhash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100000
    )  # 100000 iterations
    return binascii.hexlify(salt).decode("ascii") + binascii.hexlify(pwdhash).decode(
        "ascii"
    )


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verifies a password against a stored hash."""
    salt = binascii.unhexlify(stored_password[:32])
    pwdhash = binascii.unhexlify(stored_password[32:])
    calculated_hash = hashlib.pbkdf2_hmac(
        "sha256", provided_password.encode("utf-8"), salt, 100000
    )
    return calculated_hash == pwdhash


def main():
    """
    Prompts the user for an index and retrieves the corresponding value from id_sequence.
    """
    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        return

    try:
        index = int(sys.argv[1])
    except ValueError:
        print("Error: Index must be an integer.")
        return

    value = get_id_at_index(index)

    if value != -1:
        print(f"Value at index {index}: {value}")


if __name__ == "__main__":
    main()

