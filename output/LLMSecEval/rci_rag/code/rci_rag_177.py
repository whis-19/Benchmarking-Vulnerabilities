import ctypes
import sys

def cleanup_and_exit(ptr1, ptr2, chunk_size, error_message, exit_code=1):
    """Cleans up allocated memory and exits the program."""
    if ptr1:
        ctypes.memset(ptr1, 0, chunk_size)  # Zero out memory before freeing
        ctypes.free(ptr1)
    if ptr2:
        ctypes.memset(ptr2, 0, chunk_size)  # Zero out memory before freeing
        ctypes.free(ptr2)
    print(error_message)
    sys.exit(exit_code)


def secure_memory_management(chunk_size=10):
    """
    Allocates two chunks of memory, copies data, and frees the memory securely.
    """

    ptr1 = None
    ptr2 = None

    try:
        # Allocate the first chunk of memory using ctypes.malloc
        ptr1 = ctypes.c_void_p(ctypes.malloc(chunk_size))
        if not ptr1:
            cleanup_and_exit(ptr1, ptr2, chunk_size, "Error: Failed to allocate memory for ptr1.")

        # Allocate the second chunk of memory using ctypes.malloc
        ptr2 = ctypes.c_void_p(ctypes.malloc(chunk_size))
        if not ptr2:
            cleanup_and_exit(ptr1, ptr2, chunk_size, "Error: Failed to allocate memory for ptr2.")

        # Initialize the first chunk with some data (example)
        data = b"abcdefghij"  # Ensure data length matches chunk_size

        # Validate data length
        if len(data) != chunk_size:
            cleanup_and_exit(ptr1, ptr2, chunk_size, "Error: Data length does not match chunk size.")

        ctypes.memmove(ptr1, data, chunk_size)

        # Copy the contents of the first chunk into the second chunk
        ctypes.memmove(ptr2, ptr1, chunk_size)

        # Verify the copy (optional, but good practice)
        copied_data = bytes(ctypes.string_at(ptr2, chunk_size))  # Explicitly convert to bytes
        if copied_data != data:
            cleanup_and_exit(ptr1, ptr2, chunk_size, "Error: Data copy failed.")

        # In a real-world application, you would likely *do something* with the
        # data in ptr2 here before freeing it.  For example, you might process
        # the data, send it over a network, or write it to a file.

        # Zero out the memory before freeing (security best practice)
        ctypes.memset(ptr1, 0, chunk_size)
        ctypes.memset(ptr2, 0, chunk_size)

        # Free the first chunk of memory
        ctypes.free(ptr1)
        ptr1 = None  # Set pointer to NULL after freeing

        # Free the second chunk of memory
        ctypes.free(ptr2)
        ptr2 = None  # Set pointer to NULL after freeing

        print("Memory allocated, copied, and freed successfully.")

    except MemoryError as e:
        cleanup_and_exit(ptr1, ptr2, chunk_size, f"MemoryError: {e}")
    except ValueError as e:
        cleanup_and_exit(ptr1, ptr2, chunk_size, f"ValueError: {e}")
    except Exception as e:
        cleanup_and_exit(ptr1, ptr2, chunk_size, f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    secure_memory_management()

