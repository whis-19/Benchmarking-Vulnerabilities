import ctypes
import os
import logging  # Import the logging module

# Configure logging (optional, but recommended for real applications)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def allocate_and_free_buffer(buffer_size, iterations):
    """
    Allocates a buffer of a specified size and then frees it in a loop,
    demonstrating safe memory management practices.

    Args:
        buffer_size: The size of the buffer to allocate (in bytes).
        iterations: The number of times to allocate and free the buffer.
    """

    for i in range(iterations):
        buffer = None  # Initialize buffer to None
        try:
            # Allocate the buffer using ctypes to mimic C-style memory allocation
            buffer = ctypes.create_string_buffer(buffer_size)

            # Check if allocation was successful.  While ctypes.create_string_buffer
            # raises an exception on allocation failure, this is a good practice
            # for other allocation methods.
            if buffer is None:
                raise MemoryError("Failed to allocate buffer.")

            # Simulate using the buffer (e.g., writing data to it).
            # Important:  Ensure the size of the data written does not exceed buffer_size.
            if buffer_size > 0:  # Add this check before memmove
                data_to_write = os.urandom(min(buffer_size, 16))  # Generate random data
                ctypes.memmove(buffer, data_to_write, len(data_to_write)) # Use memmove for safety

        except MemoryError as e:
            logging.error(f"Memory allocation error: {e}")  # Use logging
            # Handle the error gracefully.  In a real application, you might
            # log the error, attempt to recover, or terminate the program.
            # Ensure the system is in a safe state.
            return  # Exit the function to prevent further iterations.

        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")  # Use logging
            return

        finally:
            # Ensure the buffer is freed, even if exceptions occur.
            if buffer is not None:
                # Simulate freeing the buffer.  In ctypes, the buffer is managed
                # by Python's garbage collector, so explicit deallocation isn't needed.
                # However, this demonstrates the pattern of freeing memory and setting
                # the pointer to None, which is essential in languages like C/C++.
                buffer = None  # Set to None to prevent reuse.
                print(f"Buffer freed in iteration {i+1}")

    print("Buffer allocation and freeing completed successfully.")


# Example usage:
if __name__ == "__main__":
    buffer_size = 1024  # Size of the buffer in bytes
    iterations = 5      # Number of times to allocate and free the buffer

    allocate_and_free_buffer(buffer_size, iterations)

