import threading
import time

# Global lock for thread synchronization
data_lock = threading.Lock()

# Volatile variable to ensure visibility across threads
dataStart_volatile = 0  # Use a global variable to simulate shared data
dataLimit_volatile = 10 # Example limit

def getData(thread_id):
    """
    Check if the dataStart is less than or equal to dataLimit.
    If so, acquire a thread lock, increase the dataStart by 1, and then unlock the thread.
    Print which thread is currently accessing the data.  Uses a global variable and lock for thread safety.
    """
    global dataStart_volatile  # Access the global variable
    global dataLimit_volatile

    while True:  # Loop to simulate continuous data access
        with data_lock:  # Acquire the lock before accessing shared resources
            if dataStart_volatile <= dataLimit_volatile:
                dataStart_volatile += 1
                print(f"Thread {thread_id}: Accessed data. dataStart = {dataStart_volatile}")
            else:
                print(f"Thread {thread_id}: Data limit reached. Exiting.")
                break  # Exit the loop when the limit is reached

        time.sleep(0.1)  # Simulate some work being done


def main():
    """
    Main function to create and start multiple threads.
    Limits the number of threads created.
    """
    num_threads = 3  # Limit the number of threads
    threads = []

    for i in range(num_threads):
        thread = threading.Thread(target=getData, args=(i + 1,))  # Pass thread ID
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()  # Wait for all threads to complete

    print("All threads finished.")


if __name__ == "__main__":
    main()

