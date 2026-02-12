import threading
import time
import logging
import random  # For more realistic sleep times
import os  # For environment variables

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')

# Define a global lock for thread synchronization
lock = threading.Lock()

# Volatile variable to ensure visibility across threads
dataStart = 0  # Initialize dataStart
dataLimit = 10  # Set a data limit

# Add a mechanism to signal threads to stop
shutdown_event = threading.Event()

# --- Configuration and Validation ---
MAX_THREADS = 10  # Define a maximum number of threads
DEFAULT_THREADS = 5

# Get the number of threads from an environment variable, with validation
try:
    NUM_THREADS = int(os.environ.get("NUM_THREADS", DEFAULT_THREADS))
    if NUM_THREADS <= 0 or NUM_THREADS > MAX_THREADS:
        NUM_THREADS = DEFAULT_THREADS  # Revert to default if invalid
        logging.warning(f"Invalid NUM_THREADS environment variable. Using default value: {DEFAULT_THREADS}")
except (ValueError, TypeError):
    NUM_THREADS = DEFAULT_THREADS
    logging.warning(f"Invalid NUM_THREADS environment variable. Using default value: {DEFAULT_THREADS}")

DATA_LIMIT_MAX = 100  # Maximum allowed value for dataLimit
DEFAULT_DATA_LIMIT = 10

try:
    DATA_LIMIT = int(os.environ.get("DATA_LIMIT", DEFAULT_DATA_LIMIT))
    if DATA_LIMIT <= 0 or DATA_LIMIT > DATA_LIMIT_MAX:
        DATA_LIMIT = DEFAULT_DATA_LIMIT
        logging.warning(f"Invalid DATA_LIMIT environment variable. Using default value: {DEFAULT_DATA_LIMIT}")
except (ValueError, TypeError):
    DATA_LIMIT = DEFAULT_DATA_LIMIT
    logging.warning(f"Invalid DATA_LIMIT environment variable. Using default value: {DEFAULT_DATA_LIMIT}")


def getData(thread_id):
    """
    Safely increments a shared counter (dataStart) using a lock.

    Args:
        thread_id: An identifier for the thread (e.g., thread number).
    """
    global dataStart, DATA_LIMIT  # Access the global variables

    while not shutdown_event.is_set():  # Check for shutdown signal
        with lock:  # Acquire the lock before accessing shared resources
            if dataStart <= DATA_LIMIT:
                current_value = dataStart
                dataStart += 1
                logging.info(f"Accessed data, current value = {current_value}, incremented to {dataStart}")
            else:
                logging.info("Reached data limit. Exiting.")
                break  # Exit the loop if the limit is reached

        # Simulate some work outside the critical section with a random delay
        time.sleep(random.uniform(0.05, 0.15))  # More realistic sleep


def main():
    """
    Creates and starts multiple threads to access and increment the shared counter.
    """
    threads = []

    try:
        for i in range(NUM_THREADS):
            thread = threading.Thread(target=getData, args=(i + 1,), name=f"Thread-{i+1}")  # Pass thread ID and name
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()  # Wait for all threads to complete

        logging.info("All threads finished.")

    except Exception as e:
        logging.error(f"An error occurred in main: {e}")
    finally:
        shutdown_event.set()  # Signal threads to stop on error or completion
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=1)  # Give threads a chance to exit gracefully
                if thread.is_alive():
                    logging.warning(f"Thread {thread.name} did not terminate gracefully.")


if __name__ == "__main__":
    main()

