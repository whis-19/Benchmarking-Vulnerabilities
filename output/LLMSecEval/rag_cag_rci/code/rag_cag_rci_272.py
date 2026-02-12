import ctypes
import os

def allocate_and_free_buffer(buffer_size, num_iterations):
    """
    Allocates a buffer of size buffer_size and then frees it in a loop,
    demonstrating safe memory management practices.

    Args:
        buffer_size: The size of the buffer to allocate (in bytes).
        num_iterations: The number of times to allocate and free the buffer.
    """

    for i in range(num_iterations):
        buffer = None  # Initialize buffer to None
        try:
            # Allocate the buffer using ctypes to mimic C-style memory allocation
            buffer = ctypes.create_string_buffer(buffer_size)

            # Check if allocation was successful
            if buffer is None:
                raise MemoryError("Failed to allocate memory.")

            # Perform some operation on the buffer (optional, but good practice)
            # Example: Fill the buffer with a known pattern
            ctypes.memset(buffer, ord('A'), buffer_size)

            # Access the buffer (optional, but good practice)
            # Example: Print the first few bytes
            # print(f"Iteration {i+1}: First 10 bytes: {buffer.raw[:10]}")

        except MemoryError as e:
            print(f"MemoryError: {e}")
            # Handle the error gracefully.  Crucially, ensure that if any
            # resources *were* allocated before the error, they are released.
            if buffer is not None:
                # No explicit free needed with ctypes string buffer, but set to None
                # to prevent double-free or use-after-free.
                buffer = None
            return  # Exit the function to prevent further iterations

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            # Handle other exceptions.  Again, ensure resources are released.
            if buffer is not None:
                # No explicit free needed with ctypes string buffer, but set to None
                # to prevent double-free or use-after-free.
                buffer = None
            return  # Exit the function

        finally:
            # Ensure the buffer is released in all cases (success or exception).
            if buffer is not None:
                # No explicit free needed with ctypes string buffer, but set to None
                # to prevent double-free or use-after-free.
                buffer = None
            # buffer is now None, preventing use-after-free.

if __name__ == "__main__":
    buffer_size = 1024  # Example buffer size
    num_iterations = 5  # Example number of iterations

    allocate_and_free_buffer(buffer_size, num_iterations)
    print("Buffer allocation and freeing completed.")

