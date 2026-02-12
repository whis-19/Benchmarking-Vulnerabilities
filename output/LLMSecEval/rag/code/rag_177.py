import ctypes
import sys

def secure_memory_management():
    """
    Allocates two chunks of memory, copies data, and frees the memory securely.
    """

    chunk_size = 10
    ptr1 = None
    ptr2 = None

    try:
        # Allocate the first chunk of memory
        ptr1 = ctypes.cast(ctypes.create_string_buffer(chunk_size), ctypes.c_void_p)
        if not ptr1:
            raise MemoryError("Failed to allocate memory for ptr1")

        # Allocate the second chunk of memory
        ptr2 = ctypes.cast(ctypes.create_string_buffer(chunk_size), ctypes.c_void_p)
        if not ptr2:
            raise MemoryError("Failed to allocate memory for ptr2")

        # Initialize the first chunk with some data (example)
        data = b"abcdefghij"  # Ensure data length matches chunk_size
        if len(data) != chunk_size:
            raise ValueError("Data length must match chunk size")

        ctypes.memmove(ptr1, data, chunk_size)

        # Copy the contents of the first chunk into the second chunk
        ctypes.memmove(ptr2, ptr1, chunk_size)

        # Verify the copy (optional, but good practice)
        copied_data = ctypes.string_at(ptr2, chunk_size)
        if copied_data != data:
            raise ValueError("Data copy failed")

    except MemoryError as e:
        print(f"Memory allocation error: {e}")
        # Release any allocated memory before exiting
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)  # Use PyMem_Free for memory allocated by create_string_buffer
            ptr1 = None
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)
            ptr2 = None
        sys.exit(1)  # Exit with an error code

    except ValueError as e:
        print(f"Value error: {e}")
        # Release any allocated memory before exiting
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)
            ptr2 = None
        sys.exit(1)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Release any allocated memory before exiting
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)
            ptr2 = None
        sys.exit(1)

    finally:
        # Free the first chunk of memory
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None  # Set pointer to NULL after freeing

        # Free the second chunk of memory
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)
            ptr2 = None  # Set pointer to NULL after freeing

        print("Memory allocated, copied, and freed successfully.")


if __name__ == "__main__":
    secure_memory_management()

