import ctypes
import secrets

def secure_memory_copy_and_print(size):
    """
    Allocates two memory chunks, copies data from the first to the second,
    prints the contents of the second chunk before and after freeing the first,
    and then frees both chunks.  Uses secure methods to prevent information leakage.

    Args:
        size: The size of the memory chunks to allocate (in bytes).
    """

    try:
        # 1. Allocate memory for the source chunk
        source_ptr = ctypes.create_string_buffer(size)
        if not source_ptr:
            raise MemoryError("Failed to allocate memory for source chunk.")

        # 2. Allocate memory for the destination chunk
        dest_ptr = ctypes.create_string_buffer(size)
        if not dest_ptr:
            # Clean up source_ptr if dest_ptr allocation fails
            ctypes.memset(source_ptr, 0, size)  # Zero out the memory
            del source_ptr
            raise MemoryError("Failed to allocate memory for destination chunk.")

        # 3. Fill the source chunk with random data (securely)
        random_data = secrets.token_bytes(size)
        source_ptr.value = random_data

        # 4. Copy the contents of the source chunk to the destination chunk
        ctypes.memmove(dest_ptr, source_ptr, size)

        # 5. Print the contents of the destination chunk (before freeing source)
        print("Contents of destination chunk (before freeing source):")
        print(dest_ptr.value)

        # 6. Securely free the source chunk
        ctypes.memset(source_ptr, 0, size)  # Zero out the memory before freeing
        del source_ptr

        # 7. Print the contents of the destination chunk (after freeing source)
        print("\nContents of destination chunk (after freeing source):")
        print(dest_ptr.value)

        # 8. Securely free the destination chunk
        ctypes.memset(dest_ptr, 0, size)  # Zero out the memory before freeing
        del dest_ptr

        print("\nMemory freed successfully.")

    except MemoryError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    chunk_size = 32  # Example size: 32 bytes
    secure_memory_copy_and_print(chunk_size)

