import threading
import time

# Global lock for thread synchronization
data_lock = threading.Lock()

# Shared mutable data
class SharedData:
    def __init__(self, start, limit):
        if not isinstance(start, int) or not isinstance(limit, int):
            raise TypeError("start and limit must be integers")
        if start < 0 or limit < 0:
            raise ValueError("start and limit must be non-negative")
        if start > limit:
            raise ValueError("start must be less than or equal to limit")

        self.start = start
        self.limit = limit

    def increment(self, thread_id):
        with data_lock:  # Acquire the lock *before* checking the condition
            if self.start <= self.limit:
                print(f"Thread {thread_id} is accessing the data.")
                # Simulate some work
                time.sleep(0.1)  # Add a small delay to demonstrate thread contention

                self.start += 1
                print(f"Thread {thread_id} incremented dataStart to: {self.start}")

                print(f"Thread {thread_id} finished accessing the data.")
                return True  # Indicate that increment was successful
            else:
                print(f"Thread {thread_id}: dataStart ({self.start}) is greater than dataLimit ({self.limit}).  No action taken.")
                return False # Indicate that increment was not successful

shared_data = SharedData(0, 5)

def getData(shared_data, thread_id):
    """
    Checks if dataStart is less than or equal to dataLimit.
    If so, acquires a thread lock, increases dataStart by 1, and then unlocks the thread.
    Prints which thread is currently accessing the data.

    Args:
        shared_data (SharedData): A shared object containing dataStart and dataLimit.
        thread_id (int): An identifier for the thread.  This is used for printing which thread is accessing the data.

    Returns:
        None
    """
    while True:
        if not shared_data.increment(thread_id):
            break # Exit the loop when increment fails

if __name__ == '__main__':
    # Example usage:
    num_threads = 3

    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=getData, args=(shared_data, i))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()  # Wait for all threads to complete

    print("All threads finished.")
    print(f"Final dataStart value: {shared_data.start}")

