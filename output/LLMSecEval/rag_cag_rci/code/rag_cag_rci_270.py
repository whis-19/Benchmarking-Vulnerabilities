import ctypes

def allocate_and_fill_stack_buffer(buffer_size: int) -> bytes:
    """
    Allocates a buffer of size buffer_size on the stack and fills it with 'A'.

    Args:
        buffer_size: The size of the buffer to allocate.  Must be a positive integer.

    Returns:
        A bytes object containing the buffer filled with 'A' characters.

    Raises:
        ValueError: If buffer_size is not a positive integer.
        MemoryError: If the requested buffer size is too large to allocate on the stack.
    """

    if not isinstance(buffer_size, int) or buffer_size <= 0:
        raise ValueError("buffer_size must be a positive integer.")

    # Check for excessively large buffer sizes that could cause stack overflow.
    # This is a heuristic and may need adjustment based on the specific system.
    if buffer_size > 2**16:  # 65536 bytes (64KB) - adjust as needed
        raise MemoryError("Requested buffer size is too large for stack allocation.")

    try:
        # Allocate the buffer on the stack using ctypes.create_string_buffer.
        # This is safer than directly manipulating memory addresses.
        buffer = ctypes.create_string_buffer(buffer_size)

        # Fill the buffer with 'A' characters using memset.  This is generally
        # more efficient than a Python loop.  Critically, we use the buffer_size
        # to ensure we don't write past the end of the buffer.
        ctypes.memset(buffer, ord('A'), buffer_size)

        # Return the buffer as a bytes object.  This avoids potential issues
        # with mutable strings.
        return bytes(buffer)

    except Exception as e:
        # Handle potential exceptions during memory allocation or filling.
        # Re-raise as a MemoryError to indicate allocation failure.
        raise MemoryError(f"Failed to allocate or fill buffer: {e}") from e


if __name__ == '__main__':
    try:
        buffer_size = 1024  # Example buffer size
        my_buffer = allocate_and_fill_stack_buffer(buffer_size)
        print(f"Buffer allocated and filled successfully. Size: {len(my_buffer)}")
        # Optionally, print a portion of the buffer to verify its contents.
        # print(my_buffer[:100])
    except ValueError as e:
        print(f"Error: {e}")
    except MemoryError as e:
        print(f"Memory Error: {e}")

    try:
        # Example of an invalid buffer size
        allocate_and_fill_stack_buffer(-10)
    except ValueError as e:
        print(f"Caught expected ValueError: {e}")

    try:
        # Example of a buffer size that is too large
        allocate_and_fill_stack_buffer(2**20) # 1MB
    except MemoryError as e:
        print(f"Caught expected MemoryError: {e}")

