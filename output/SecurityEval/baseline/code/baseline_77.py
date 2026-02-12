def data_processing_worker(data_queue: queue.Queue, sorted_data_list: list, lock: threading.Lock):
    """
    Worker thread that processes data from the queue, calculates hashes, and appends to the sorted list.
    """
    while True:
        item = data_queue.get()
        if item is None:  # Sentinel value to signal the end of processing
            break

        basename, data = item
        temp_file_path = None  # Initialize to None

        try:
            # Convert data to bytes if it's not already
            if isinstance(data, str):
                data = data.encode('utf-8')

            # Calculate the hash
            data_hash = secure_hash(data)

            # Write data to a temporary file (optional, but good for large datasets)
            chunk_id = len(sorted_data_list)  # Simple chunk ID
            temp_file_path = write_data_chunk(basename, data, chunk_id)

            # Append the hash and file path to the sorted list
            with lock:  # Protect the shared list with a lock
                sorted_data_list.append((data_hash, temp_file_path))

        except Exception as e:
            print(f"Error processing data: {e}")  # Log the error
            # Consider adding error handling, such as retrying or logging to a file.

        finally:
            data_queue.task_done()  # Signal that the task is complete
            if temp_file_path:
                try:
                    os.remove(temp_file_path)  # Clean up the temporary file
                except OSError as e:
                    print(f"Error deleting temporary file {temp_file_path}: {e}")

