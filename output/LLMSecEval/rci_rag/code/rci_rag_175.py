import secrets
import os
import logging
import ctypes  # Import for memory zeroing

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message.log')


def zero_memory(data: bytearray) -> None:
    """Zeros out the memory occupied by a bytearray using memset."""
    size = len(data)
    try:
        ctypes.memset(ctypes.addressof(data), 0, size)
    except Exception as e:
        logging.error(f"Error zeroing memory: {e}")
        # Consider re-raising or handling the error appropriately
        raise  # Or handle more gracefully if appropriate

def secure_memory_copy(size: int) -> None:
    """
    Allocates two chunks of memory, copies the contents of the first into the second,
    and prints the contents of the second.  Uses secrets.token_bytes for secure random data
    and checks buffer sizes to prevent overflows.

    Args:
        size: The size of the memory chunks to allocate.  Must be a positive integer.

    Raises:
        ValueError: If size is not a positive integer.
        MemoryError: If memory allocation fails.
    """

    if not isinstance(size, int) or size <= 0:
        raise ValueError("Size must be a positive integer.")

    try:
        # Allocate the first chunk of memory and fill it with cryptographically secure random data.
        # secrets.token_bytes is preferred over os.urandom for generating secrets.
        chunk1 = secrets.token_bytes(size)

        # Allocate the second chunk of memory using bytearray for mutability.
        chunk2 = bytearray(size)

        # Copy the contents of the first chunk into the second chunk using slicing for safe copying
        # and to prevent buffer overflows.
        chunk2[:] = chunk1

        # Print the contents of the second chunk. Limit output to prevent information leakage
        # and avoid excessive output.  Limiting to 32 bytes.
        output_size = min(32, size)
        print(f"Copied data (first {output_size} bytes): {chunk2[:output_size]}")

        # Zero out the memory after use.  Important for security.
        zero_memory(chunk2)

    except MemoryError as e:
        logging.error(f"Memory allocation failed: {e}")
        # Suggest a strategy for the user to try a smaller size.
        print("Failed to allocate memory.  Try a significantly smaller size.  Consider a size within the range of 1 to 1024 bytes.")
        raise  # Re-raise the exception to signal failure to the caller.  This ensures the caller is aware of the failure and can handle it appropriately.
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        # No explicit memory deallocation needed in Python, garbage collection handles it.
        # However, in a more complex scenario with external resources, proper cleanup would be crucial.
        raise  # Re-raise the exception to signal failure to the caller.  This ensures the caller is aware of the failure and can handle it appropriately.


if __name__ == "__main__":
    try:
        # Get a size from the environment, or use a default.  This is safer than hardcoding.
        size = int(os.environ.get("MEMORY_SIZE", "128"))  # Default size is 128 bytes.
        secure_memory_copy(size)
    except ValueError:
        print("Invalid MEMORY_SIZE environment variable.  Must be an integer.")
    except MemoryError:
        print("Failed to allocate memory.  Try a smaller size.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

