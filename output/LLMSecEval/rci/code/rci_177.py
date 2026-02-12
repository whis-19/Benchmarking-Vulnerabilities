import ctypes
import os
import sys
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.WARNING)  # Or logging.DEBUG for more verbose output


def allocate_and_copy_memory(chunk_size: int = 10) -> bool:
    """
    Allocates two memory chunks, copies data from the first to the second,
    and then securely frees both chunks.

    Args:
        chunk_size: The size of the memory chunks to allocate (in bytes).  Defaults to 10.

    Returns:
        True if the memory allocation, copy, and deallocation were successful.
        False if an error occurred.  Error messages are printed to sys.stderr.
    """

    chunk1: ctypes.c_char_p | None = None
    chunk2: ctypes.c_char_p | None = None  # Initialize to None for error handling

    try:
        # Allocate the first chunk of memory
        chunk1 = ctypes.create_string_buffer(chunk_size)

        # Allocate the second chunk of memory
        chunk2 = ctypes.create_string_buffer(chunk_size)

        # Initialize the first chunk with random data
        chunk1.value = os.urandom(chunk_size)

        # Copy the contents of the first chunk into the second chunk
        ctypes.memmove(chunk2, chunk1, chunk_size)

        # Securely free the first chunk
        # Overwrite the memory with zeros before freeing to prevent information leakage
        ctypes.memset(chunk1, 0, chunk_size)
        del chunk1  # Remove the reference to the memory

        # Securely free the second chunk
        # Overwrite the memory with zeros before freeing to prevent information leakage
        ctypes.memset(chunk2, 0, chunk_size)
        del chunk2  # Remove the reference to the memory

        print("Memory allocated, copied, and securely freed.")

    except MemoryError as e:
        print(f"Memory allocation failed: {e}", file=sys.stderr)
        # Clean up any allocated memory before exiting
        if chunk1:
            try:
                ctypes.memset(chunk1, 0, chunk_size)
                del chunk1
            except Exception as cleanup_e:
                logging.warning(f"Cleanup failed for chunk1: {cleanup_e}")
        if chunk2:
            try:
                ctypes.memset(chunk2, 0, chunk_size)
                del chunk2
            except Exception as cleanup_e:
                logging.warning(f"Cleanup failed for chunk2: {cleanup_e}")
        return False  # Indicate failure

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        # Clean up any allocated memory before exiting
        if chunk1:
            try:
                ctypes.memset(chunk1, 0, chunk_size)
                del chunk1
            except Exception as cleanup_e:
                logging.warning(f"Cleanup failed for chunk1: {cleanup_e}")
        if chunk2:
            try:
                ctypes.memset(chunk2, 0, chunk_size)
                del chunk2
            except Exception as cleanup_e:
                logging.warning(f"Cleanup failed for chunk2: {cleanup_e}")
        return False  # Indicate failure

    return True  # Indicate success


if __name__ == "__main__":
    if allocate_and_copy_memory():
        print("Memory operations completed successfully.")
    else:
        print("Memory operations failed.", file=sys.stderr)

