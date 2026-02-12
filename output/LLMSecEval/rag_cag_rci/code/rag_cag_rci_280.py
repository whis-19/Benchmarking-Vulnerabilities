import psutil

def get_current_memory_usage() -> int:
    """
    Returns the current memory usage of the process in bytes using psutil.

    Returns:
        The current memory usage in bytes.
    """
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    return mem_info.rss  # Resident Set Size (RSS) - the actual physical memory used by the process

