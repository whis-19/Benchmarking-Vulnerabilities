import io
import socket  # Import for socket.settimeout
import select  # For more robust timeout handling

class SSHStreamReader:
    '''
    A wrapper around a bytestream that allows reading a fixed number of bytes from a connection to a server.
    '''

    MAX_BYTES_TO_READ = 1024 * 1024  # Example: 1MB maximum

    def __init__(self, stream, timeout=None):
        '''
        @param stream:  The stream to read from.  Must be a file-like object with a `read` method.
        @param timeout: Optional timeout in seconds for socket operations.
        '''
        if not hasattr(stream, 'read'):
            raise TypeError("Stream must have a 'read' method.")
        self._stream = stream
        self._timeout = timeout

        # If it's a socket, set the timeout
        if isinstance(stream, socket.socket):
            stream.settimeout(timeout)


    def read_bytes(self, num_bytes: int) -> bytes:
        '''
        Reads a fixed number of bytes from the stream.
        @param num_bytes:  The number of bytes to read.  Must be a non-negative integer.
        @return:    The read bytes.
        @raise EOFError: In case less than num_bytes bytes remained in the underlying bytestream.
        @raise ValueError: If num_bytes is negative or exceeds the maximum allowed value.
        '''
        if not isinstance(num_bytes, int):
            raise TypeError("num_bytes must be an integer.")
        if num_bytes < 0:
            raise ValueError("num_bytes must be non-negative.")
        if num_bytes > self.MAX_BYTES_TO_READ:
            raise ValueError(f"num_bytes exceeds the maximum allowed value of {self.MAX_BYTES_TO_READ}.")


        buf = io.BytesIO()
        bytes_read = 0
        try:
            while bytes_read < num_bytes:
                try:
                    # Use select for more robust timeout handling (if applicable)
                    if self._timeout is not None and isinstance(self._stream, socket.socket):
                        rlist, _, _ = select.select([self._stream], [], [], self._timeout)
                        if not rlist:
                            raise TimeoutError("Timeout occurred while waiting to read from socket.")

                    chunk = self._stream.read(num_bytes - bytes_read)
                except TimeoutError as e:
                    raise e # Re-raise TimeoutError
                except Exception:
                    # Handle potential stream errors (e.g., socket errors)
                    # Sanitize the error message
                    raise OSError("Error reading from stream.") from None  # Changed to OSError and sanitized message

                if not chunk:  # EOF
                    break

                buf.write(chunk)
                bytes_read += len(chunk)

            if bytes_read < num_bytes:
                raise EOFError(f"Expected {num_bytes} bytes, but only read {bytes_read} bytes.")

            return buf.getvalue()
        finally:
            buf.close()  # Explicitly close the BytesIO object


# Example Usage (and testing):
if __name__ == '__main__':
    # Test with a string stream
    data = b"This is a test string."
    stream = io.BytesIO(data)
    reader = SSHStreamReader(stream)

    try:
        result = reader.read_bytes(5)
        print(f"Read 5 bytes: {result}")  # Expected: b'This '

        result = reader.read_bytes(7)
        print(f"Read 7 bytes: {result}")  # Expected: b'is a te'

        result = reader.read_bytes(5)
        print(f"Read 5 bytes: {result}")  # Expected: b'st st'

        result = reader.read_bytes(5) # Should raise EOFError
    except EOFError as e:
        print(f"Caught expected EOFError: {e}")

    # Test with a socket (requires a running server) -  Illustrative only, adapt to your actual socket setup
    import socket
    server_address = ('localhost', 12345)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(server_address)
        sock.settimeout(5)  # Add a timeout to prevent indefinite hanging
        sock.listen(1)
        print('waiting for a connection')
        with sock.accept()[0] as connection:
            try:
                reader = SSHStreamReader(connection, timeout=5) # Pass the connection and timeout to SSHStreamReader
                data_from_server = reader.read_bytes(10)
                print(f"Received from server: {data_from_server}")
            except Exception as e:
                print(f"Error: {e}")


    # Test with invalid stream
    try:
        reader = SSHStreamReader(123)
    except TypeError as e:
        print(f"Caught expected TypeError: {e}")

    # Test with negative num_bytes
    stream = io.BytesIO(b"test")
    reader = SSHStreamReader(stream)
    try:
        reader.read_bytes(-1)
    except ValueError as e:
        print(f"Caught expected ValueError: {e}")

    # Test with num_bytes exceeding maximum
    stream = io.BytesIO(b"test")
    reader = SSHStreamReader(stream)
    try:
        reader.read_bytes(SSHStreamReader.MAX_BYTES_TO_READ + 1)
    except ValueError as e:
        print(f"Caught expected ValueError: {e}")


    # Test with zero num_bytes
    stream = io.BytesIO(b"test")
    reader = SSHStreamReader(stream)
    result = reader.read_bytes(0)
    print(f"Read 0 bytes: {result}") # Expected: b''

