import threading
import time

# Define a lock to protect the shared resource (dataStart)
data_lock = threading.Lock()

# Volatile variable to ensure visibility across threads
dataStart = 0  # Initialize dataStart
dataLimit = 10 # Set dataLimit
thread_count = 0 # Initialize thread_count

def getData(thread_id):
    """
    Safely increments a shared counter (dataStart) using a lock.

    Args:
        thread_id: An identifier for the thread (e.g., thread number).
    """
    global dataStart, dataLimit, thread_count  # Access the global dataStart and dataLimit

    while True:
        with data_lock:  # Acquire the lock before accessing shared resources
            if dataStart <= dataLimit:
                dataStart += 1
                print(f"Thread {thread_id}: Accessed data. dataStart = {dataStart}")
            else:
                break  # Exit the loop if dataStart exceeds dataLimit
        time.sleep(0.1)  # Simulate some work outside the critical section

def main():
    """
    Creates and starts multiple threads to access and modify the shared data.
    """
    global thread_count
    threads = []
    max_threads = 5 # Limit the number of threads

    for i in range(max_threads):
        thread_count += 1
        thread = threading.Thread(target=getData, args=(i + 1,))  # Pass thread ID
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()  # Wait for all threads to complete

    print("All threads finished.")

if __name__ == "__main__":
    main()

