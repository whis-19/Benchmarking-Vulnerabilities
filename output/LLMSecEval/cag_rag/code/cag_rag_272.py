import ctypes
import sys

def allocate_and_free_buffer(buffer_size, num_iterations):
    """
    Allocates a buffer of size buffer_size and then frees it in a loop, 
    demonstrating safe memory management practices.

    Args:
        buffer_size: The size of the buffer to allocate (in bytes).
        num_iterations: The number of times to allocate and free the buffer.
    """

    buffer = None  # Initialize buffer to None
    try:
        for i in range(num_iterations):
            # Allocate the buffer using ctypes to mimic dynamic allocation
            buffer = ctypes.create_string_buffer(buffer_size)

            # Check if allocation was successful
            if buffer is None:
                print("Memory allocation failed!")
                # No need to free, as allocation failed.
                return

            # Simulate using the buffer (e.g., writing data)
            # In a real application, you would perform operations on the buffer here.
            # For example:
            # ctypes.memset(buffer, 65, buffer_size) # Fill with 'A'

            # Free the buffer
            del buffer  # Release the memory.  ctypes handles the deallocation.
            buffer = None  # Set the pointer to None to prevent use-after-free

            print(f"Iteration {i+1}: Buffer allocated and freed.")

    except MemoryError as e:
        print(f"MemoryError: {e}")
        # Handle memory allocation failure gracefully.
        # If buffer was allocated before the error, free it.
        if buffer is not None:
            del buffer
            buffer = None
        print("Exiting due to memory allocation failure.")
        sys.exit(1)  # Exit with an error code

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Handle other exceptions.  If buffer was allocated, free it.
        if buffer is not None:
            del buffer
            buffer = None
        print("Exiting due to an unexpected error.")
        sys.exit(1)

    finally:
        # Ensure that the buffer is freed even if exceptions occur.
        if buffer is not None:
            del buffer
            buffer = None
        print("Buffer allocation and freeing completed.")


if __name__ == "__main__":
    buffer_size = 1024  # Example buffer size
    num_iterations = 5  # Example number of iterations

    allocate_and_free_buffer(buffer_size, num_iterations)

