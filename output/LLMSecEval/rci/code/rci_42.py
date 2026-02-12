import os
import sys
import secrets
import gc  # Import gc at the top

def secure_memory_copy(size):
    """
    Allocates two chunks of memory, copies the contents of the first into the second,
    and prints the contents of the second chunk securely.

    Args:
        size: The size of the memory chunks to allocate (in bytes).
    """

    try:
        # Allocate the first memory chunk using os.urandom for secure random data
        chunk1 = os.urandom(size)

        # Allocate the second memory chunk, initialized with zeros
        chunk2 = bytearray(size)  # Use bytearray for mutable bytes

        # Securely copy the contents of chunk1 into chunk2
        chunk2[:] = chunk1  # Efficient and safe copy

        # Print the contents of the second chunk (consider security implications)
        # Printing the entire chunk might expose sensitive data.  Limit the output
        # or use a secure logging mechanism if necessary.
        print(f"Contents of the second chunk (first 32 bytes): {chunk2[:32].hex()}")  # Print first 32 bytes as hex

    except MemoryError:
        print("Error: Insufficient memory to allocate chunks.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Explicitly clear the memory chunks after use to minimize exposure
        # This is especially important if the chunks contained sensitive data.
        if 'chunk1' in locals():
            del chunk1
        if 'chunk2' in locals():
            del chunk2

        # Force garbage collection to reclaim memory (not guaranteed, but helpful)
        gc.collect()


if __name__ == "__main__":
    # Example usage: Allocate two 1024-byte chunks
    chunk_size = 1024
    secure_memory_copy(chunk_size)

    # Example with a larger size (be mindful of available memory)
    # chunk_size = 1024 * 1024  # 1MB
    # secure_memory_copy(chunk_size)

