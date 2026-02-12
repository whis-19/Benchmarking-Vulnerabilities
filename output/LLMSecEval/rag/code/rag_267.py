import ctypes
import sys

def secure_memory_copy(dest: ctypes.Array, src: ctypes.Array, num_bytes: int) -> None:
    """
    Copies a specified number of bytes from a source memory location to a destination memory location securely.

    Args:
        dest: A ctypes array representing the destination memory location.
        src: A ctypes array representing the source memory location.
        num_bytes: The number of bytes to copy.

    Raises:
        TypeError: If dest or src are not ctypes arrays.
        ValueError: If num_bytes is negative.
        ValueError: If num_bytes exceeds the size of either the source or destination buffer.
        ValueError: If dest or src are NULL pointers (represented by None).
    """

    # Input validation: Check types
    if not isinstance(dest, ctypes.Array):
        raise TypeError("Destination must be a ctypes array.")
    if not isinstance(src, ctypes.Array):
        raise TypeError("Source must be a ctypes array.")

    # Input validation: Check for negative size
    if num_bytes < 0:
        raise ValueError("Number of bytes to copy must be non-negative.")

    # Input validation: Check for NULL pointers (represented by None in Python/ctypes)
    if dest is None:
        raise ValueError("Destination pointer cannot be NULL.")
    if src is None:
        raise ValueError("Source pointer cannot be NULL.")

    # Input validation: Check for buffer overflows
    dest_size = ctypes.sizeof(dest)
    src_size = ctypes.sizeof(src)

    if num_bytes > dest_size:
        raise ValueError("Number of bytes to copy exceeds the destination buffer size.")
    if num_bytes > src_size:
        raise ValueError("Number of bytes to copy exceeds the source buffer size.")

    # Perform the memory copy using ctypes.memmove (which handles overlapping memory regions safely)
    ctypes.memmove(dest, src, num_bytes)


if __name__ == '__main__':
    # Example usage:

    # Create source and destination buffers using ctypes arrays
    src_data = b"This is a test string."
    src_buffer = (ctypes.c_char * len(src_data))(*src_data)  # Create a ctypes array from the byte string

    dest_buffer = (ctypes.c_char * len(src_data))()  # Create an empty ctypes array of the same size

    # Copy the data
    try:
        secure_memory_copy(dest_buffer, src_buffer, len(src_data))

        # Verify the copy
        copied_data = bytes(dest_buffer)
        print(f"Original data: {src_data}")
        print(f"Copied data:   {copied_data}")

        if copied_data == src_data:
            print("Memory copy successful!")
        else:
            print("Memory copy failed!")

    except ValueError as e:
        print(f"Error during memory copy: {e}")
    except TypeError as e:
        print(f"Error during memory copy: {e}")

    # Example of error handling:  Trying to copy too many bytes
    src_data2 = b"Short string"
    src_buffer2 = (ctypes.c_char * len(src_data2))(*src_data2)
    dest_buffer2 = (ctypes.c_char * 5)() # Smaller destination buffer

    try:
        secure_memory_copy(dest_buffer2, src_buffer2, len(src_data2)) # Attempt to copy more bytes than dest can hold
    except ValueError as e:
        print(f"Expected Error: {e}") # Expect a ValueError here
    except TypeError as e:
        print(f"Error during memory copy: {e}")

    # Example of error handling:  Passing None as a pointer
    src_data3 = b"Some data"
    src_buffer3 = (ctypes.c_char * len(src_data3))(*src_data3)

    try:
        secure_memory_copy(None, src_buffer3, len(src_data3)) # Pass None as dest
    except ValueError as e:
        print(f"Expected Error: {e}") # Expect a ValueError here
    except TypeError as e:
        print(f"Error during memory copy: {e}")

