import ctypes
import os
import mmap
import secrets  # For generating random data

def secure_memory_copy(dest, src, num_bytes):
    """
    Copies a specified number of bytes from one memory location to another securely.

    Args:
        dest:  The destination memory address (as an integer).
        src:   The source memory address (as an integer).
        num_bytes: The number of bytes to copy.

    Raises:
        TypeError: If dest, src, or num_bytes are not of the correct type.
        ValueError: If num_bytes is negative.
        OSError: If the memory copy operation fails.

    Returns:
        None.  The function modifies the memory at the destination address directly.
    """

    if not isinstance(dest, int):
        raise TypeError("Destination address (dest) must be an integer.")
    if not isinstance(src, int):
        raise TypeError("Source address (src) must be an integer.")
    if not isinstance(num_bytes, int):
        raise TypeError("Number of bytes (num_bytes) must be an integer.")

    if num_bytes < 0:
        raise ValueError("Number of bytes (num_bytes) must be non-negative.")

    if num_bytes == 0:
        return  # Nothing to copy

    try:
        # Use ctypes.memmove for safe memory copying (handles overlapping regions)
        ctypes.memmove(dest, src, num_bytes)

    except Exception as e:
        raise OSError(f"Memory copy operation failed: {e}") from e


def example_usage(message):
    """
    Example demonstrating the usage of secure_memory_copy.

    Args:
        message: The string message to copy.
    """

    message_bytes = message.encode('utf-8')
    num_bytes = len(message_bytes)

    # Securely allocate a buffer using mmap
    try:
        buffer = mmap.mmap(-1, num_bytes, prot=mmap.PROT_READ | mmap.PROT_WRITE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    except OSError as e:
        print(f"Error allocating memory: {e}")
        return

    # Get the memory addresses of the source (message) and destination (buffer)
    source_buffer = ctypes.create_string_buffer(message_bytes)
    src_address = ctypes.addressof(source_buffer)
    dest_address = ctypes.addressof(ctypes.c_char.from_buffer(buffer))  # Correct mmap address

    try:
        secure_memory_copy(dest_address, src_address, num_bytes)

        # Verify the copy (using a temporary buffer)
        temp_buffer = ctypes.create_string_buffer(num_bytes)
        ctypes.memmove(ctypes.addressof(temp_buffer), dest_address, num_bytes)
        copied_message = temp_buffer.raw.decode('utf-8')

        print(f"Original message: {message}")
        print(f"Copied message: {copied_message}")

        if message == copied_message:
            print("Memory copy successful!")
        else:
            print("Memory copy failed!")

    except (TypeError, ValueError, OSError) as e:
        print(f"Error during memory copy: {e}")

    finally:
        # Securely erase the buffers after use.
        try:
            # Overwrite mmap buffer with random data multiple times
            for _ in range(3):  # Overwrite 3 times
                random_data = secrets.token_bytes(num_bytes)
                buffer.seek(0)
                buffer.write(random_data)
            buffer.close()
        except Exception as e:
            print(f"Error erasing mmap buffer: {e}")

        try:
            # Zero out the source buffer immediately
            ctypes.memset(src_address, 0, num_bytes)
        except Exception as e:
            print(f"Error erasing source buffer: {e}")


# Example usage:
if __name__ == "__main__":
    message = "This is a secret message!"
    example_usage(message)

    message2 = "Another message to test."
    example_usage(message2)

