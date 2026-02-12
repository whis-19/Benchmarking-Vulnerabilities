import ctypes
import sys

def allocate_and_copy_memory():
    """
    Allocates two chunks of memory, copies data from the first to the second,
    and then frees both chunks.  Includes error handling and null pointer assignment.
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

        # Initialize the first chunk with some data (important for demonstrating copy)
        data = b"abcdefghij"  # Ensure data length matches size
        ctypes.memmove(ptr1, data, size)

        # Copy the contents of the first chunk into the second chunk
        ctypes.memmove(ptr2, ptr1, size)

        # Verify the copy (optional, but good practice)
        copied_data = ctypes.string_at(ptr2, size)
        if copied_data != data:
            raise ValueError("Memory copy failed: Data mismatch")

    except MemoryError as e:
        print(f"Memory allocation error: {e}")
        # Release any allocated memory before exiting
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)  # Correctly free memory
            ptr1 = None  # Set to NULL
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)  # Correctly free memory
            ptr2 = None  # Set to NULL
        return False  # Indicate failure

    except ValueError as e:
        print(f"Value error: {e}")
        # Release any allocated memory before exiting
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)  # Correctly free memory
            ptr1 = None  # Set to NULL
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)  # Correctly free memory
            ptr2 = None  # Set to NULL
        return False  # Indicate failure

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Release any allocated memory before exiting
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)  # Correctly free memory
            ptr1 = None  # Set to NULL
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)  # Correctly free memory
            ptr2 = None  # Set to NULL
        return False  # Indicate failure

    finally:
        # Free the first chunk of memory
        if ptr1:
            ctypes.pythonapi.PyMem_Free(ptr1)  # Correctly free memory
            ptr1 = None  # Set to NULL

        # Free the second chunk of memory
        if ptr2:
            ctypes.pythonapi.PyMem_Free(ptr2)  # Correctly free memory
            ptr2 = None  # Set to NULL

    return True  # Indicate success


if __name__ == "__main__":
    if allocate_and_copy_memory():
        print("Memory allocation, copy, and deallocation successful.")
    else:
        print("Memory operation failed.")

