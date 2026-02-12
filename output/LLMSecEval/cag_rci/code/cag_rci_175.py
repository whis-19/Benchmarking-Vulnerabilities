import os
import sys
import hashlib
import gc  # Import if you want to try forcing garbage collection

MAX_SIZE = 1024 * 1024  # 1MB maximum

def secure_clear_memory(data):
    """Securely clears the contents of a bytearray."""
    if data is not None and isinstance(data, bytearray):
        try:
            data[:] = b'\x00' * len(data)
        except Exception as e:
            print(f"Error clearing memory: {e}")
        finally:
            del data # Remove reference


def secure_memory_copy(size):
    """
    Allocates two chunks of memory, copies the contents of the first into the second,
    and securely clears the memory.

    Args:
        size: The size of the memory chunks to allocate (in bytes).
    """

    chunk1 = None
    chunk2 = None

    try:
        if size <= 0:
            print("Error: Memory size must be a positive integer.")
            return

        if size > MAX_SIZE:
            print(f"Error: Memory size exceeds maximum allowed size ({MAX_SIZE} bytes).")
            return

        if size > sys.maxsize:
            print("Error: Memory size is too large and may cause integer overflow.")
            return

        # Allocate the first memory chunk using os.urandom for secure random data
        chunk1 = os.urandom(size)

        # Allocate the second memory chunk
        chunk2 = bytearray(size)  # Use bytearray for mutable bytes

        # Securely copy the contents of chunk1 into chunk2
        chunk2[:] = chunk1  # Efficient and safe copy

        # *** REMOVE PRINTING OF SENSITIVE DATA ***
        # Instead of printing, hash the data to verify the copy
        hash1 = hashlib.sha256(chunk1).hexdigest()
        hash2 = hashlib.sha256(chunk2).hexdigest()

        if hash1 == hash2:
            print("Memory copied successfully (verified with SHA-256 hashes).")
        else:
            print("Error: Memory copy failed (hash mismatch).")

        # Zero out the memory chunks after use to prevent data leakage
        # This is crucial for security.
        secure_clear_memory(chunk2)
        chunk1 = None  # Remove reference to allow garbage collection

        print("Memory cleared.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure memory is cleared even if an error occurs
        secure_clear_memory(chunk2)
        chunk1 = None
        #gc.collect() # Try to force garbage collection (optional)


if __name__ == "__main__":
    # Get the desired memory chunk size from the command line
    if len(sys.argv) > 1:
        try:
            size = int(sys.argv[1])
            secure_memory_copy(size)
        except ValueError:
            print("Error: Invalid memory size.  Please provide an integer.")
    else:
        # Default size if no argument is provided
        default_size = 64  # Example size
        print(f"Using default memory size: {default_size} bytes")
        secure_memory_copy(default_size)

