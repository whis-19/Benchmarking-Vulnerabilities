import threading
import time
import logging

# Configure logging for security-related events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables (shared resources) - use with caution and synchronization
dataStart = 0  # Initial data value
dataLimit = 10 # Limit for the data
lock = threading.Lock()  # Mutex lock for synchronizing access to shared resources
MAX_THREADS = 5 # Limit the number of threads to prevent resource exhaustion

# Volatile type modifier is not directly available in Python.  Instead, rely on proper locking.
# We will treat dataStart as volatile by always accessing it under the lock.

def getData(thread_id):
    """
    Safely increments a shared data value within a thread, using a mutex lock.

    Args:
        thread_id: An identifier for the thread (e.g., thread number).
    """
    global dataStart, dataLimit  # Access the global shared variables

    while True:
        with lock:  # Acquire the lock before accessing shared resources (RAII)
            if dataStart <= dataLimit:
                dataStart += 1
                print(f"Thread {thread_id}: Accessed data. dataStart = {dataStart}")
                # Simulate some work being done
                time.sleep(0.1)  # Simulate some work
            else:
                print(f"Thread {thread_id}: Reached data limit.")
                break  # Exit the loop if the limit is reached

        # Release the lock (automatically released by 'with' statement)
        time.sleep(0.01) # Add a small delay to reduce contention

def worker(thread_id):
    """
    Worker function for each thread.

    Args:
        thread_id: An identifier for the thread.
    """
    try:
        getData(thread_id)
    except Exception as e:
        logging.error(f"Thread {thread_id}: An error occurred: {e}")


if __name__ == "__main__":
    threads = []
    for i in range(MAX_THREADS):
        try:
            thread = threading.Thread(target=worker, args=(i + 1,))
            threads.append(thread)
            thread.start()
        except threading.ThreadError as e:
            logging.error(f"Failed to create thread {i+1}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while creating thread {i+1}: {e}")

    for thread in threads:
        thread.join()  # Wait for all threads to complete

    print("All threads finished.")

