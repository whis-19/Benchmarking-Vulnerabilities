import os
import hashlib
import threading
import queue
import tempfile
import re
import secrets
import logging
import uuid
import shutil
import time  # For simulating foo() and backpressure

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

# Constants for security
MAX_FILE_SIZE = 1024 * 1024 * 10  # 10MB - Adjust as needed
HASH_ALGORITHM = 'sha256'  # Use a strong hashing algorithm
SORTED_DATA_FILE = "sorted_data.txt"  # File to store sorted data
MAX_QUEUE_SIZE = 100  # Limit the queue size to prevent memory exhaustion
FILENAME_REGEX = r"^[a-zA-Z0-9_\-.]+$"
MAX_FILENAME_LENGTH = 255  # Limit filename length to prevent ReDoS
MAX_TOTAL_DATA_SIZE = 1024 * 1024 * 100  # 100MB total data limit

# Simulated foo() function (replace with your actual implementation)
def foo():
    """Simulates a function that returns a basename and data."""
    time.sleep(0.1)  # Simulate some work
    # Simulate occasional errors or malicious behavior
    if secrets.randbelow(100) == 0:  # 1% chance of error
        return "very_long_filename_" * 100, "data"  # Simulate ReDoS
    if secrets.randbelow(100) == 1:  # 1% chance of error
        return None, None  # Simulate end of data
    return "safe_filename.txt", secrets.token_hex(16)  # Example data


def secure_hash(data: bytes) -> str:
    """Calculates a secure hash of the data."""
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(data)
    return hasher.hexdigest()


def write_data_chunk(basename: str, data: bytes, chunk_id: uuid.UUID, temp_dir: str) -> str:
    """Writes a data chunk to a temporary file."""
    if len(data) > MAX_FILE_SIZE:
        raise ValueError(f"Data size exceeds maximum allowed size ({MAX_FILE_SIZE} bytes)")

    basename = os.path.basename(basename)
    basename = os.path.normpath(basename)
    basename = basename.replace("..", "")

    if len(basename) > MAX_FILENAME_LENGTH:
        raise ValueError(f"Basename too long.  Maximum length is {MAX_FILENAME_LENGTH}")

    if not re.match(FILENAME_REGEX, basename):
        raise ValueError(f"Invalid basename: {basename}.  Must match {FILENAME_REGEX}")

    temp_file_path = os.path.join(temp_dir, f"{basename}_{chunk_id}.tmp")

    # Double-check file existence (unlikely with UUID, but good practice)
    while os.path.exists(temp_file_path):
        chunk_id = uuid.uuid4()  # Generate a new UUID
        temp_file_path = os.path.join(temp_dir, f"{basename}_{chunk_id}.tmp")
        logging.warning(f"File already exists, regenerating filename: {temp_file_path}") # Log the event

    try:
        with open(temp_file_path, "wb") as f:
            f.write(data)
    except OSError as e:
        raise OSError(f"Error writing to temporary file: {e}")

    return temp_file_path


def data_processing_worker(data_queue: queue.Queue, sorted_data_list: list, lock: threading.Lock, temp_dir_path: str):
    """Worker thread that processes data from the queue."""
    while True:
        item = data_queue.get()
        if item is None:
            break

        basename, data = item
        temp_file_path = None

        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            data_hash = secure_hash(data)

            # Use UUID for chunk ID
            chunk_id = uuid.uuid4()
            temp_file_path = write_data_chunk(basename, data, chunk_id, temp_dir_path)

            with lock:
                sorted_data_list.append((data_hash, temp_file_path))

        except Exception as e:
            logging.exception(f"Error processing data for basename: {basename}")  # Log with stack trace

        finally:
            data_queue.task_done()


def dataSorting():
    """Continuously takes (basename, data) key-value pairs from foo() function and sorts it."""

    data_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
    sorted_data_list = []
    lock = threading.Lock()

    num_workers = os.cpu_count()
    workers = []

    with tempfile.TemporaryDirectory() as temp_dir_path:
        # Disk space monitoring (example)
        disk_space_threshold = 0.8  # 80% disk usage
        total_data_processed = 0
        queue_full_count = 0  # Track how often the queue is full

        for _ in range(num_workers):
            worker = threading.Thread(target=data_processing_worker, args=(data_queue, sorted_data_list, lock, temp_dir_path))
            workers.append(worker)
            worker.daemon = True
            worker.start()

        try:
            while True:
                # Queue Monitoring and Simulated Backpressure
                if data_queue.qsize() >= MAX_QUEUE_SIZE * 0.9:  # Near capacity
                    queue_full_count += 1
                    logging.warning(f"Queue near capacity ({data_queue.qsize()}/{MAX_QUEUE_SIZE}).  Consider backpressure.")
                    time.sleep(0.5)  # Simulate backpressure by pausing
                    if queue_full_count > 10:
                        logging.critical("Queue consistently full.  Possible DoS.  Terminating.")
                        break # Terminate if consistently full
                else:
                    queue_full_count = 0 # Reset counter if queue is not full

                basename, data = foo()

                if basename is None and data is None:
                    break

                if not isinstance(data, (str, bytes)):
                    logging.warning(f"Invalid data type received: {type(data)}. Skipping.")
                    continue

                # Check disk space
                total, used, free = shutil.disk_usage(temp_dir_path)
                if (used / total) > disk_space_threshold:
                    logging.error("Disk space threshold exceeded. Stopping processing.")
                    break

                # Check total data processed
                data_length = len(data) if isinstance(data, bytes) else len(data.encode('utf-8'))
                total_data_processed += data_length
                if total_data_processed > MAX_TOTAL_DATA_SIZE:  # Define MAX_TOTAL_DATA_SIZE
                    logging.error("Total data size limit exceeded. Stopping processing.")
                    break

                # Monitor foo() output (example)
                if len(basename) > 100:
                    logging.warning(f"Long basename received from foo(): {basename}")

                data_queue.put((basename, data))

        except KeyboardInterrupt:
            print("Interrupted by user.")

        finally:
            for _ in range(num_workers):
                data_queue.put(None)

            data_queue.join()

            for worker in workers:
                worker.join()

            sorted_data_list.sort(key=lambda x: x[0])

            try:
                with open(SORTED_DATA_FILE, "w") as outfile:
                    for data_hash, temp_file_path in sorted_data_list:
                        outfile.write(f"{data_hash},{temp_file_path}\n")
                logging.info(f"Sorted data written to {SORTED_DATA_FILE}")
            except OSError as e:
                logging.error(f"Error writing to sorted data file: {e}")


if __name__ == "__main__":
    dataSorting()

