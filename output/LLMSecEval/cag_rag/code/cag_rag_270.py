import ctypes

def allocate_and_fill_stack_buffer(buffer_size):
    """
    Allocates a buffer of size buffer_size on the stack and fills it with 'A'.

    Args:
        buffer_size: The size of the buffer to allocate.  Must be a positive integer.

    Returns:
        A string containing the buffer filled with 'A' characters, or None if an error occurred.
    """

    if not isinstance(buffer_size, int):
        print("Error: buffer_size must be an integer.")
        return None

    if buffer_size <= 0:
        print("Error: buffer_size must be a positive integer.")
        return None

    try:
        # Allocate a buffer on the stack using ctypes.create_string_buffer.
        # This is the closest we can get to stack allocation in Python.
        buffer = ctypes.create_string_buffer(buffer_size)

        # Fill the buffer with 'A' characters.  Using ctypes.memset for efficiency.
        ctypes.memset(buffer, ord('A'), buffer_size)

        # Convert the buffer to a Python string.  Decode using 'ascii' to ensure
        # that we only have ASCII characters.
        return buffer.raw.decode('ascii')

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


if __name__ == '__main__':
    buffer_size = 10
    filled_buffer = allocate_and_fill_stack_buffer(buffer_size)

    if filled_buffer:
        print(f"Buffer content: {filled_buffer}")
        print(f"Buffer length: {len(filled_buffer)}")

    buffer_size = 0
    filled_buffer = allocate_and_fill_stack_buffer(buffer_size)

    buffer_size = -1
    filled_buffer = allocate_and_fill_stack_buffer(buffer_size)

    buffer_size = "abc"
    filled_buffer = allocate_and_fill_stack_buffer(buffer_size)

