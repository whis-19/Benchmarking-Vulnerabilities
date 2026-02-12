import ctypes

def allocate_copy_free():
    """
    Allocates two chunks of memory, copies the contents of the first into the second,
    and then frees both chunks.  Handles potential errors during allocation.
    """

    size = 10
    ptr1 = None
    ptr2 = None

    try:
        # Allocate the first chunk of memory
        ptr1 = ctypes.cast(ctypes.create_string_buffer(size), ctypes.c_void_p)
        if not ptr1:
            raise MemoryError("Failed to allocate memory for ptr1")

        # Allocate the second chunk of memory
        ptr2 = ctypes.cast(ctypes.create_string_buffer(size), ctypes.c_void_p)
        if not ptr2:
            raise MemoryError("Failed to allocate memory for ptr2")

        # Initialize the first chunk with some data (optional, but good practice)
        data = b"abcdefghij"  # Example data
        ctypes.memmove(ptr1, data, size)

        # Copy the contents of the first chunk into the second chunk
        ctypes.memmove(ptr2, ptr1, size)

    except MemoryError as e:
        print(f"Memory allocation error: {e}")
        # Release any allocated memory before exiting
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None  # Set to None after freeing
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)
            ptr2 = None  # Set to None after freeing
        return

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Release any allocated memory before exiting
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None  # Set to None after freeing
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)
            ptr2 = None  # Set to None after freeing
        return

    finally:
        # Free the first chunk of memory
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)
            ptr1 = None  # Set to None after freeing

        # Free the second chunk of memory
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)
            ptr2 = None  # Set to None after freeing

# Example usage:
allocate_copy_free()

