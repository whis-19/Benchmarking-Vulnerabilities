import threading
import time

# Global lock for thread synchronization
data_lock = threading.Lock()

def getData(dataStart, dataLimit, thread_id):
    """
    Checks if dataStart is less than or equal to dataLimit.
    If so, acquires a thread lock, increases dataStart by 1, and then unlocks the thread.
    Prints which thread is currently accessing the data.

    Args:
        dataStart (int): The starting value of the data.  This is passed by value, so changes within the function do not affect the caller.  Consider using a mutable object (like a list) if you need to modify the original value.
        dataLimit (int): The limit of the data.
        thread_id (int): An identifier for the thread.  Important for debugging and logging.

    Returns:
        int: The updated value of dataStart (after incrementing, if applicable).  Returns the original value if no increment occurred.  This is important for the caller to know if the value was updated.
    """

    if dataStart <= dataLimit:
        with data_lock:  # Acquire the lock using a context manager (ensures release)
            print(f"Thread {thread_id} is accessing the data.")
            dataStart += 1
            print(f"Thread {thread_id} incremented dataStart to {dataStart}")
            return dataStart  # Return the updated value
    else:
        print(f"Thread {thread_id}: dataStart ({dataStart}) is greater than dataLimit ({dataLimit}). No action taken.")
        return dataStart # Return the original value if no increment occurred


if __name__ == '__main__':
    # Example usage:
    data_start = 0
    data_limit = 5
    num_threads = 3
    threads = []

    def worker(thread_id):
        nonlocal data_start  # Access the data_start variable from the outer scope
        while data_start <= data_limit:
            new_data_start = getData(data_start, data_limit, thread_id)
            if new_data_start > data_start:
                data_start = new_data_start  # Update the data_start value
            else:
                break # Exit the loop if no increment occurred
            time.sleep(0.1)  # Simulate some work

    for i in range(num_threads):
        thread = threading.Thread(target=worker, args=(i,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("All threads finished.")
    print(f"Final data_start value: {data_start}")

