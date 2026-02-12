import secrets
import sys

def secure_memory_copy(data_size: int) -> None:
    """
    Allocates two chunks of memory, copies the contents of the first chunk into the second,
    and then prints the contents of the second chunk.  Uses secure methods to prevent
    buffer overflows and other memory-related vulnerabilities.

    Args:
        data_size: The size of the memory chunks to allocate (in bytes).  Must be a positive integer.
    """

    if not isinstance(data_size, int) or data_size <= 0:
        raise ValueError("data_size must be a positive integer.")

    try:
        # Allocate the first chunk of memory using secrets.token_bytes for secure random data.
        # This avoids potential issues with predictable data patterns.
        source_data = secrets.token_bytes(data_size)

        # Allocate the second chunk of memory.  Use bytearray for mutable data.
        destination_data = bytearray(data_size)

        # Check if allocation was successful (Python handles memory allocation internally,
        # but we can check for potential errors by catching exceptions).
        if source_data is None or destination_data is None:
            raise MemoryError("Failed to allocate memory.")

        # Securely copy the data from the source to the destination using slicing.
        # Slicing inherently prevents out-of-bounds writes because it will only copy
        # up to the size of the destination.
        destination_data[:] = source_data

        # Print the contents of the destination buffer.  Limit the output to prevent
        # excessively large prints that could cause denial-of-service.
        max_print_length = 100  # Limit the output to 100 bytes.
        print(f"Copied data (first {min(data_size, max_print_length)} bytes): {destination_data[:max_print_length]}")

    except MemoryError as e:
        print(f"Memory allocation error: {e}")
        # No explicit deallocation needed in Python, garbage collection handles it.
        # However, in a more complex scenario with external resources, you would
        # release them here.
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Handle other potential exceptions.
    finally:
        # No explicit deallocation needed in Python.  The garbage collector will
        # handle the memory.  Setting the variables to None is good practice
        # to release references.
        source_data = None
        destination_data = None


if __name__ == "__main__":
    try:
        data_size = int(input("Enter the size of the memory chunks (in bytes): "))
        secure_memory_copy(data_size)
    except ValueError:
        print("Invalid input. Please enter a positive integer for the data size.")
    except Exception as e:
        print(f"An error occurred: {e}")

