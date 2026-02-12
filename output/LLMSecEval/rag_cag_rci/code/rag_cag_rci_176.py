import ctypes
import os

def secure_memory_copy(data: bytes):
    """
    Allocates two chunks of memory, copies data from the first to the second,
    prints the contents of the second chunk, frees the first chunk,
    prints the contents of the second chunk again, and then frees the second chunk.

    Args:
        data: The bytes to copy into the allocated memory.
    """

    size = len(data)

    # Allocate memory for the first chunk
    ptr1 = None
    try:
        ptr1 = ctypes.cast(ctypes.create_string_buffer(size), ctypes.c_void_p)
        if not ptr1:
            raise MemoryError("Failed to allocate memory for ptr1")

        # Copy data into the first chunk
        ctypes.memmove(ptr1, data, size)

        # Allocate memory for the second chunk
        ptr2 = None
        try:
            ptr2 = ctypes.cast(ctypes.create_string_buffer(size), ctypes.c_void_p)
            if not ptr2:
                raise MemoryError("Failed to allocate memory for ptr2")

            # Copy data from the first chunk to the second chunk
            ctypes.memmove(ptr2, ptr1, size)

            # Print the contents of the second chunk
            print("Contents of second chunk (after copy):", ctypes.string_at(ptr2, size))

            # Free the memory allocated to the first chunk
            ctypes.pythonapi.PyMem_Free(ptr1)  # Use PyMem_Free for memory allocated with create_string_buffer
            ptr1 = None  # Set pointer to None after freeing

            # Print the contents of the second chunk again (should still be valid)
            print("Contents of second chunk (after freeing ptr1):", ctypes.string_at(ptr2, size))

        except MemoryError as e:
            print(f"Memory allocation error: {e}")
            if ptr1:
                ctypes.pythonapi.PyMem_Free(ptr1)
                ptr1 = None
            raise  # Re-raise the exception to signal failure

        except Exception as e:
            print(f"An error occurred: {e}")
            if ptr1:
                ctypes.pythonapi.PyMem_Free(ptr1)
                ptr1 = None
            if ptr2:
                ctypes.pythonapi.PyMem_Free(ptr2)
                ptr2 = None
            raise  # Re-raise the exception to signal failure

        finally:
            # Free the memory allocated to the second chunk
            if ptr2:
                ctypes.pythonapi.PyMem_Free(ptr2)
                ptr2 = None  # Set pointer to None after freeing

    except MemoryError as e:
        print(f"Memory allocation error: {e}")
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None
        raise  # Re-raise the exception to signal failure

    except Exception as e:
        print(f"An error occurred: {e}")
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None
        raise  # Re-raise the exception to signal failure


if __name__ == "__main__":
    data = os.urandom(32)  # Example data: 32 random bytes
    try:
        secure_memory_copy(data)
    except Exception as e:
        print(f"Program terminated due to an error: {e}")

