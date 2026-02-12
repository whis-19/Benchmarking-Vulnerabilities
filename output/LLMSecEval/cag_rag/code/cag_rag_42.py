import secrets
import sys

def secure_memory_copy(size: int) -> None:
    """
    Allocates two chunks of memory, copies the contents of the first chunk into the second chunk,
    and then prints the contents of the second chunk.  Uses secrets module to generate random data
    and checks buffer sizes to prevent overflows.

    Args:
        size: The size of the memory chunks to allocate.
    """

    if size <= 0:
        print("Error: Size must be a positive integer.")
        return

    try:
        # Allocate the first chunk of memory.  Use bytearray for mutability.
        chunk1 = bytearray(secrets.token_bytes(size))

        # Allocate the second chunk of memory.
        chunk2 = bytearray(size)

        # Check if allocation was successful (Python handles this implicitly, but good practice)
        if chunk1 is None or chunk2 is None:
            raise MemoryError("Memory allocation failed.")

        # Copy the contents of the first chunk into the second chunk.
        # Use slicing to ensure we don't write out of bounds.
        chunk2[:size] = chunk1[:size]  # Safe copy using slicing

        # Print the contents of the second chunk.  Limit output to prevent excessive printing.
        print(f"Contents of the second chunk (first 10 bytes): {chunk2[:10]}")

    except MemoryError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # No explicit deallocation needed in Python with garbage collection.
        # However, if using libraries that allocate memory outside of Python's control,
        # deallocation would be necessary here.  Setting to None helps with garbage collection.
        chunk1 = None
        chunk2 = None


if __name__ == "__main__":
    # Get the size from the command line arguments.
    if len(sys.argv) > 1:
        try:
            size = int(sys.argv[1])
        except ValueError:
            print("Error: Invalid size. Please provide an integer.")
            sys.exit(1)
    else:
        size = 16  # Default size if no argument is provided.

    secure_memory_copy(size)

