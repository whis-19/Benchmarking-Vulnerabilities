import ctypes
import sys

def secure_memory_copy(data: bytes):
    """
    Allocates two chunks of memory, copies data from the first to the second,
    prints the contents of the second, frees the first, prints the second again,
    and then frees the second.  Includes robust error handling and memory safety.

    Args:
        data: The bytes to copy into the allocated memory.
    """

    size = len(data)

    # Allocate the first chunk of memory
    ptr1 = None
    try:
        ptr1 = ctypes.cast(ctypes.create_string_buffer(size), ctypes.c_void_p)
        if not ptr1:
            raise MemoryError("Failed to allocate memory for ptr1")

        # Copy data into the first chunk
        ctypes.memmove(ptr1, data, size)

        # Allocate the second chunk of memory
        ptr2 = None
        try:
            ptr2 = ctypes.cast(ctypes.create_string_buffer(size), ctypes.c_void_p)
            if not ptr2:
                raise MemoryError("Failed to allocate memory for ptr2")

            # Copy data from the first chunk to the second chunk
            ctypes.memmove(ptr2, ptr1, size)

            # Print the contents of the second chunk
            print("Contents of second chunk (after copy):", ctypes.string_at(ptr2, size))

            # Free the first chunk of memory
            ctypes.pythonapi.PyMem_Free(ptr1)  # Use PyMem_Free for memory allocated with create_string_buffer
            ptr1 = None  # Set pointer to NULL

            # Print the contents of the second chunk again (should still be valid)
            print("Contents of second chunk (after freeing ptr1):", ctypes.string_at(ptr2, size))

        except MemoryError as e:
            print(f"Error allocating memory: {e}")
            if ptr2:
                ctypes.pythonapi.PyMem_Free(ptr2)
                ptr2 = None
            if ptr1:
                ctypes.pythonapi.PyMem_Free(ptr1)
                ptr1 = None
            raise  # Re-raise the exception to signal failure

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            if ptr2:
                ctypes.pythonapi.PyMem_Free(ptr2)
                ptr2 = None
            if ptr1:
                ctypes.pythonapi.PyMem_Free(ptr1)
                ptr1 = None
            raise  # Re-raise the exception to signal failure

        finally:
            # Free the second chunk of memory
            if ptr2:
                ctypes.pythonapi.PyMem_Free(ptr2)
                ptr2 = None  # Set pointer to NULL

    except MemoryError as e:
        print(f"Error allocating memory: {e}")
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None
        raise  # Re-raise the exception to signal failure

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None
        raise  # Re-raise the exception to signal failure


if __name__ == '__main__':
    try:
        data = b"This is a test string for memory allocation and copying."
        secure_memory_copy(data)
        print("Memory operations completed successfully.")
    except Exception as e:
        print(f"An error occurred during memory operations: {e}")
        sys.exit(1)  # Exit with an error code

