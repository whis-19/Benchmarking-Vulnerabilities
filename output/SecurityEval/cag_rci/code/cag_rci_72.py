import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class SharedData:
    """
    Encapsulates shared data and provides thread-safe access to it.
    """
    def __init__(self, start, limit):
        """
        Initializes the SharedData object.

        Args:
            start (int): The starting value. Must be non-negative and less than or equal to limit.
            limit (int): The upper limit. Must be non-negative.

        Raises:
            ValueError: If start or limit are invalid.
        """
        if not isinstance(start, int) or not isinstance(limit, int):
            raise TypeError("start and limit must be integers")
        if start < 0 or limit < 0:
            raise ValueError("start and limit must be non-negative")
        if start > limit:
            raise ValueError("start must be less than or equal to limit")

        # Add a maximum limit to prevent resource exhaustion
        MAX_LIMIT = 1000  # Example maximum limit
        if limit > MAX_LIMIT:
            raise ValueError(f"Limit exceeds maximum allowed value ({MAX_LIMIT})")

        self.data_start = start
        self.data_limit = limit
        self.lock = threading.Lock()

    def get_and_increment(self, thread_id):
        """
        Atomically retrieves the current value and increments it if it's within the limit.

        Args:
            thread_id (int): An identifier for the thread.

        Returns:
            bool: True if the value was retrieved and incremented, False otherwise.
        """
        with self.lock:
            if self.data_start <= self.data_limit:
                logging.debug(f"Thread {thread_id} is accessing the data.  Current data_start: {self.data_start}") # Use DEBUG level
                self.data_start += 1
                logging.debug(f"Thread {thread_id} updated data_start to: {self.data_start}") # Use DEBUG level
                return True  # Indicate that data was processed
            else:
                logging.info(f"Thread {thread_id}: data_start ({self.data_start}) exceeds data_limit ({self.data_limit}).  No update performed.") # Use INFO level
                return False # Indicate that data was not processed


def worker(shared_data, thread_id):
    try:
        while True:
            if not shared_data.get_and_increment(thread_id):
                break  # Exit the loop when data_start exceeds data_limit
            time.sleep(0.1)  # Simulate some work
    except Exception as e:
        logging.error(f"Thread {thread_id} encountered an error: {e}", exc_info=True) # Log the full exception
        # Consider a mechanism to signal other threads to stop if a critical error occurs


if __name__ == '__main__':
    # Example usage:
    start_value = 0
    limit_value = 10
    num_threads = 5
    #threads = [] # No longer needed

    try:
        shared_data = SharedData(start_value, limit_value)
    except ValueError as e:
        print(f"Error: {e}")
        exit()

    # Use a ThreadPoolExecutor to limit the number of concurrent threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        for i in range(num_threads):
            executor.submit(worker, shared_data, i)

    # The executor's context manager waits for all tasks to complete

    print("All threads finished.")
    print(f"Final data_start value: {shared_data.data_start}")

