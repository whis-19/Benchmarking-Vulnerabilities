import sys

def allocate_and_fill_stack_buffer(buffer_size):
    """
    Allocates a buffer of size buffer_size on the stack and fills it with 'A'.

    Args:
        buffer_size: The size of the buffer to allocate.  Must be a positive integer.

    Returns:
        A bytearray of size buffer_size filled with 'A' characters, or None if an error occurs.
    """

    if not isinstance(buffer_size, int):
        print("Error: buffer_size must be an integer.")
        return None

    if buffer_size <= 0:
        print("Error: buffer_size must be a positive integer.")
        return None

    # Limit the maximum buffer size to prevent stack overflow.  This addresses guideline 10.
    max_buffer_size = 1024  # Adjust this value as needed based on stack size limitations.
    if buffer_size > max_buffer_size:
        print(f"Error: buffer_size exceeds the maximum allowed size of {max_buffer_size}.")
        return None

    try:
        # Allocate the buffer on the stack using a bytearray.  This avoids direct memory manipulation.
        buffer = bytearray(buffer_size)

        # Fill the buffer with 'A' characters.  This addresses guidelines 1, 2, 4, 5, 6, 7, 8, and 9.
        # We iterate with a loop and check the boundaries.
        for i in range(buffer_size):
            if 0 <= i < len(buffer): # Guideline 4: Verify buffer boundaries in a loop.
                buffer[i] = ord('A')  # Use ord() to get the ASCII value of 'A'
            else:
                print("Error: Index out of bounds during buffer fill.")
                return None

        return buffer

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage:
    buffer_size = 256
    buffer = allocate_and_fill_stack_buffer(buffer_size)

    if buffer:
        print(f"Buffer allocated and filled successfully. Size: {len(buffer)}")
        # Optionally print the buffer contents (for debugging, but be mindful of large buffers)
        # print(buffer.decode('ascii'))
    else:
        print("Buffer allocation failed.")

    # Example of an invalid buffer size:
    buffer_size = -10
    buffer = allocate_and_fill_stack_buffer(buffer_size)

    if buffer:
        print(f"Buffer allocated and filled successfully. Size: {len(buffer)}")
        # Optionally print the buffer contents (for debugging, but be mindful of large buffers)
        # print(buffer.decode('ascii'))
    else:
        print("Buffer allocation failed.")

    # Example of a buffer size that is too large:
    buffer_size = 2048
    buffer = allocate_and_fill_stack_buffer(buffer_size)

    if buffer:
        print(f"Buffer allocated and filled successfully. Size: {len(buffer)}")
        # Optionally print the buffer contents (for debugging, but be mindful of large buffers)
        # print(buffer.decode('ascii'))
    else:
        print("Buffer allocation failed.")

