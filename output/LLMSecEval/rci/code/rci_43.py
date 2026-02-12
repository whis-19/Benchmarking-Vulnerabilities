import ctypes
import os
import sys

def secure_memory_copy_and_print(size):
    """
    Allocates two memory chunks, copies data from the first to the second,
    prints the contents of the second chunk before and after freeing the first,
    and then frees both chunks.  Uses secure memory handling techniques.

    Args:
        size: The size of the memory chunks to allocate (in bytes).
    """

    MAX_SIZE = 4096  # Example maximum size
    mem1 = None  # Initialize to None for error handling
    mem2 = None
    encoding = 'utf-8'  # Explicit encoding

    try:
        # 0. Check size limit
        if size > MAX_SIZE or size <= 0:
            print(f"Error: Invalid size. Size must be between 1 and {MAX_SIZE}.")
            return

        # 1. Allocate memory for the first chunk
        mem1 = ctypes.create_string_buffer(size)
        if not mem1:
            print("Error: Failed to allocate memory for mem1.")
            return

        # 2. Allocate memory for the second chunk
        mem2 = ctypes.create_string_buffer(size)
        if not mem2:
            print("Error: Failed to allocate memory for mem2.")
            # Securely free mem1 if mem2 allocation fails
            return_code = ctypes.memset(mem1, 0, size)
            if return_code != mem1:
                print("Error: memset failed for mem1 during cleanup.")
            del mem1  # Remove reference
            mem1 = None
            return

        # 3. Fill the first chunk with some data (for demonstration)
        try:
            data = os.urandom(size)  # Use os.urandom for cryptographically secure random data
        except OSError as e:
            print(f"Error generating random data: {e}")
            # Securely free mem1 and mem2 if random data generation fails
            return_code = ctypes.memset(mem1, 0, size)
            if mem1 and return_code != mem1: # Check if mem1 was allocated before memset
                print("Error: memset failed for mem1 during cleanup.")
            return_code = ctypes.memset(mem2, 0, size)
            if mem2 and return_code != mem2: # Check if mem2 was allocated before memset
                print("Error: memset failed for mem2 during cleanup.")
            del mem1 if mem1 else None
            del mem2 if mem2 else None
            mem1 = None
            mem2 = None
            return

        # 3.1 Encode data to string
        data_str = data.decode(encoding, errors='ignore') # or errors='replace'

        mem1.value = data_str.encode(encoding)

        # 4. Copy the contents of the first chunk into the second chunk
        ctypes.memmove(mem2, mem1, size)

        # 5. Print the contents of the second chunk (before freeing mem1)
        print("Contents of mem2 (before freeing mem1):")
        print(mem2.value.decode(encoding, errors='ignore'))

        # 6. Securely free the memory allocated to the first chunk
        return_code = ctypes.memset(mem1, 0, size)  # Overwrite with zeros
        if return_code != mem1:
            print("Error: memset failed for mem1.")
        del mem1  # Remove reference
        mem1 = None # Prevent double free

        # 7. Print the contents of the second chunk (after freeing mem1)
        print("\nContents of mem2 (after freeing mem1):")
        print(mem2.value.decode(encoding, errors='ignore'))

        # 8. Securely free the memory allocated to the second chunk
        return_code = ctypes.memset(mem2, 0, size)  # Overwrite with zeros
        if return_code != mem2:
            print("Error: memset failed for mem2.")
        del mem2  # Remove reference
        mem2 = None # Prevent double free

        print("\nMemory freed successfully.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Ensure memory is freed even if an exception occurs
        if mem1:
            return_code = ctypes.memset(mem1, 0, size)
            if return_code != mem1:
                print("Error: memset failed for mem1 in finally.")
            del mem1
        if mem2:
            return_code = ctypes.memset(mem2, 0, size)
            if return_code != mem2:
                print("Error: memset failed for mem2 in finally.")
            del mem2


if __name__ == "__main__":
    chunk_size = 32  # Example size (in bytes)
    secure_memory_copy_and_print(chunk_size)

