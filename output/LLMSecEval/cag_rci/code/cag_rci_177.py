import ctypes
import logging

logging.basicConfig(level=logging.INFO)

MAX_CHUNK_SIZE = 4096  # Example maximum chunk size

def secure_memory_copy_and_free(data_to_copy, is_c_string=False):
    """
    Allocates memory, copies data, and securely frees.

    Args:
        data_to_copy: The data to copy (bytes).
        is_c_string:  Whether the data should be treated as a C-style string (null-terminated).

    Returns:
        True on success, False on failure.
    """

    chunk_size = 0
    chunk1 = None
    chunk2 = None

    try:
        # Determine chunk size dynamically, but with a maximum limit
        chunk_size = len(data_to_copy) + (1 if is_c_string else 0)  # +1 for null termination if data is intended to be a C-style string
        chunk_size = min(chunk_size, MAX_CHUNK_SIZE)

        # Validate chunk size
        if chunk_size > MAX_CHUNK_SIZE:
            raise ValueError("Data size exceeds maximum allowed chunk size.")

        # Allocate the first chunk
        chunk1 = ctypes.cast(ctypes.malloc(chunk_size), ctypes.c_void_p)
        if not chunk1:
            raise MemoryError("Failed to allocate memory for chunk1.")

        # Initialize the entire buffer to zeros
        ctypes.memset(chunk1, 0, chunk_size)

        # Allocate the second chunk
        chunk2 = ctypes.cast(ctypes.malloc(chunk_size), ctypes.c_void_p)
        if not chunk2:
            raise MemoryError("Failed to allocate memory for chunk2.")

        # Initialize the entire buffer to zeros
        ctypes.memset(chunk2, 0, chunk_size)

        # Validate data size (STRICTLY LESS THAN)
        if len(data_to_copy) >= chunk_size:
            raise ValueError("Data to copy exceeds chunk size.")

        # Sanitize input data (example: ensure ASCII)
        try:
            data_to_copy.decode('ascii')  # Check if data is ASCII
        except UnicodeDecodeError:
            raise ValueError("Data contains non-ASCII characters.")


        # Copy data into chunk1
        ctypes.memmove(chunk1, data_to_copy, len(data_to_copy))

        # Null terminate (if needed)
        if is_c_string:
            ctypes.memset(chunk1 + len(data_to_copy), 0, 1)

        # Copy the contents of chunk1 into chunk2
        ctypes.memmove(chunk2, chunk1, chunk_size)

        logging.info("Memory allocated, copied, and securely freed successfully.")
        return True  # Indicate success

    except (MemoryError, ValueError) as e:
        logging.error(f"Error: {e}")
        return False  # Indicate failure
    except OSError as e:
        logging.error(f"OSError during memory allocation: {e}")
        return False
    except Exception as e:
        logging.exception(f"Unexpected error: {e}") # Log the full traceback
        return False
    finally:
        # Securely free chunk1
        if chunk1:
            try:
                ctypes.memset(chunk1, 0, chunk_size)
                ctypes.free(chunk1)
            except Exception as e:
                logging.error(f"Error freeing chunk1: {e}")

        # Securely free chunk2
        if chunk2:
            try:
                ctypes.memset(chunk2, 0, chunk_size)
                ctypes.free(chunk2)
            except Exception as e:
                logging.error(f"Error freeing chunk2: {e}")


if __name__ == "__main__":
    data = b"abcdefghij"
    success = secure_memory_copy_and_free(data)
    if success:
        print("Memory operation successful.")
    else:
        print("Memory operation failed.")

    data_c_string = b"hello"
    success = secure_memory_copy_and_free(data_c_string, is_c_string=True)
    if success:
        print("C-string memory operation successful.")
    else:
        print("C-string memory operation failed.")

    data_non_ascii = b"hello\xffworld"
    success = secure_memory_copy_and_free(data_non_ascii)
    if success:
        print("Non-ASCII memory operation successful.")
    else:
        print("Non-ASCII memory operation failed.")

