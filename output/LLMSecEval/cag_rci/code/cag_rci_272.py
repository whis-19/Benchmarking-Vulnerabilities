import logging
import threading

# Configure logging (example)
logging.basicConfig(level=logging.ERROR)

class ByteBuffer:
    """
    A context manager for creating and managing a zeroed-out byte buffer.

    This class provides a secure way to handle sensitive data by ensuring that the
    buffer is zeroed and deleted when it's no longer needed.  It is designed to be
    used with a 'with' statement.

    Thread-safe access to the buffer is provided using a lock.
    """
    MAX_SIZE = 1024 * 1024  # Example: 1MB maximum

    def __init__(self, size):
        """
        Initializes a ByteBuffer with the specified size.

        Args:
            size: The size of the byte buffer in bytes.

        Raises:
            ValueError: If the size exceeds the maximum allowed size.
        """
        if size > self.MAX_SIZE:
            raise ValueError(f"Buffer size exceeds maximum allowed size of {self.MAX_SIZE} bytes.")
        self.size = size
        self.buffer = None
        self._lock = threading.Lock()  # For thread safety

    def __enter__(self):
        """
        Enters the 'with' block.  Allocates the byte buffer and returns it.

        Returns:
            A bytearray representing the allocated buffer.
        """
        with self._lock:
            self.buffer = bytearray(self.size)
            return self.buffer

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exits the 'with' block.  Zeroes out the buffer and deletes it.

        Args:
            exc_type: The type of exception that occurred (if any).
            exc_val: The exception value (if any).
            exc_tb: The traceback (if any).
        """
        with self._lock:
            try:
                if self.buffer:
                    self.buffer[:] = b'\x00' * len(self.buffer)
                    del self.buffer
            except Exception as e:
                logging.error(f"Error zeroing buffer: {e}", exc_info=True)
                if exc_type is None:  # Only re-raise if no exception occurred in the 'with' block
                    raise  # Re-raise the exception
            finally:
                self.buffer = None

# Example usage:
if __name__ == '__main__':
    with ByteBuffer(1024) as buf:
        # Use the buffer here
        buf[0:5] = b"hello"
        print(buf)
    # Buffer is automatically zeroed and deleted after the 'with' block

