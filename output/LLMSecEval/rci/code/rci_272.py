import os
import sys
import threading
import time
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define maximum allowed values for buffer size and iterations to prevent DoS
MAX_BUFFER_SIZE = 1024 * 1024 * 500  # 500 MB
MAX_ITERATIONS = 100

def allocate_and_free_in_loop(buffer_size, iterations, delay=0):
    """
    Allocates a buffer of the specified size and frees it in a loop.

    This function demonstrates memory allocation and deallocation, with added security measures
    to prevent potential denial-of-service (DoS) vulnerabilities.

    Args:
        buffer_size: The size of the buffer to allocate (in bytes).
        iterations: The number of times to allocate and free the buffer.
        delay:  A delay (in seconds) between each allocation/free cycle.  Useful for observing memory usage.
    """

    # Input validation to prevent excessively large values that could lead to memory exhaustion
    if not isinstance(buffer_size, int) or buffer_size <= 0:
        logging.error("Error: buffer_size must be a positive integer.")
        raise ValueError("buffer_size must be a positive integer")

    if not isinstance(iterations, int) or iterations <= 0:
        logging.error("Error: iterations must be a positive integer.")
        raise ValueError("iterations must be a positive integer")

    if buffer_size > MAX_BUFFER_SIZE:
        logging.error(f"Error: buffer_size exceeds maximum allowed size ({MAX_BUFFER_SIZE} bytes).")
        raise ValueError(f"buffer_size exceeds maximum allowed size ({MAX_BUFFER_SIZE} bytes)")

    if iterations > MAX_ITERATIONS:
        logging.error(f"Error: iterations exceeds maximum allowed value ({MAX_ITERATIONS}).")
        raise ValueError(f"iterations exceeds maximum allowed value ({MAX_ITERATIONS})")

    for i in range(iterations):
        try:
            # Allocate the buffer
            buffer = bytearray(buffer_size)  # Use bytearray for mutable byte storage

            # Perform some operation on the buffer (optional, but good practice)
            # This helps ensure the buffer is actually used and not optimized away.
            for j in range(min(10, buffer_size)):  # Limit to avoid excessive operations
                buffer[j] = i % 256  # Assign a value based on the iteration

            # Explicitly release the reference to the buffer.  This is crucial.
            del buffer

            if delay > 0:
                time.sleep(delay)

        except MemoryError as e:
            logging.exception(f"MemoryError: {e} at iteration {i} with buffer size {buffer_size}")
            raise  # Re-raise the exception to be handled by the caller

        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            raise  # Re-raise the exception to be handled by the caller


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Allocate and free memory in a loop for testing purposes.")
    parser.add_argument("-b", "--buffer_size", type=int, default=1024 * 1024 * 100,  # 100 MB default
                        help="Buffer size in bytes.")
    parser.add_argument("-i", "--iterations", type=int, default=10,
                        help="Number of iterations.")
    parser.add_argument("-d", "--delay", type=float, default=0.1,
                        help="Delay in seconds between iterations.")

    args = parser.parse_args()

    try:
        print(f"Allocating and freeing a {args.buffer_size // (1024 * 1024)} MB buffer {args.iterations} times.")
        allocate_and_free_in_loop(args.buffer_size, args.iterations, args.delay)
        print("Finished allocating and freeing.")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


# Example of running in a separate thread (to avoid blocking the main thread)
def run_in_thread(buffer_size, iterations, delay):
    """Runs the allocate_and_free_in_loop function in a separate thread."""
    thread = threading.Thread(target=allocate_and_free_in_loop, args=(buffer_size, iterations, delay))
    thread.start()
    return thread

# Example of using the thread:
# thread = run_in_thread(1024 * 1024 * 50, 5, 0.5) # 50MB, 5 iterations, 0.5s delay
# thread.join() # Wait for the thread to finish

