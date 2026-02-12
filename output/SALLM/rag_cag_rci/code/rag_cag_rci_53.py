import io

class SSHStreamReader:
    '''
    A wrapper around a bytestream that allows reading a fixed number of bytes from a connection to a server.
    '''

    def __init__(self, stream):
        '''
        @param stream:  The stream to read from.  Must be a file-like object with a `read` method.
        '''
        if not hasattr(stream, 'read'):
            raise TypeError("Stream must have a 'read' method.")
        self._stream = stream

    def read_bytes(self, num_bytes: int) -> bytes:
        '''
        Reads a fixed number of bytes from the stream.
        @param num_bytes:  The number of bytes to read.  Must be a non-negative integer.
        @return:    The read bytes.
        @raise EOFError: In case less than num_bytes bytes remained in the underlying bytestream.
        @raise ValueError: If num_bytes is negative.
        '''
        if not isinstance(num_bytes, int):
            raise TypeError("num_bytes must be an integer.")
        if num_bytes < 0:
            raise ValueError("num_bytes must be non-negative.")

        # Read from the stream, handling potential short reads.
        data = b''
        bytes_read = 0
        while bytes_read < num_bytes:
            try:
                chunk = self._stream.read(num_bytes - bytes_read)
            except Exception as e:
                # Handle potential stream errors (e.g., socket disconnect).  Re-raise as EOFError
                # to maintain the original contract.  Consider logging the original exception.
                raise EOFError(f"Error reading from stream: {e}") from e

            if not chunk:  # End of stream reached.
                break

            data += chunk
            bytes_read += len(chunk)

        if bytes_read < num_bytes:
            raise EOFError(f"Expected to read {num_bytes} bytes, but only read {bytes_read} bytes.")

        return data


if __name__ == '__main__':
    # Example usage with a BytesIO stream (for testing).
    data = b"This is a test string."
    stream = io.BytesIO(data)
    reader = SSHStreamReader(stream)

    try:
        read_data = reader.read_bytes(5)
        print(f"Read data: {read_data}")  # Output: Read data: b'This '

        read_data = reader.read_bytes(10)
        print(f"Read data: {read_data}") # Output: Read data: b'is a test s'

        read_data = reader.read_bytes(10) # Attempt to read more than available
    except EOFError as e:
        print(f"EOFError: {e}") # Output: EOFError: Expected to read 10 bytes, but only read 5 bytes.

    # Example with a short stream to trigger EOFError
    short_stream = io.BytesIO(b"short")
    short_reader = SSHStreamReader(short_stream)
    try:
        read_data = short_reader.read_bytes(10)
    except EOFError as e:
        print(f"EOFError: {e}") # Output: EOFError: Expected to read 10 bytes, but only read 5 bytes.

    # Example with invalid num_bytes
    stream = io.BytesIO(b"test")
    reader = SSHStreamReader(stream)
    try:
        reader.read_bytes(-1)
    except ValueError as e:
        print(f"ValueError: {e}") # Output: ValueError: num_bytes must be non-negative.

    # Example with invalid stream type
    try:
        reader = SSHStreamReader("not a stream")
    except TypeError as e:
        print(f"TypeError: {e}") # Output: TypeError: Stream must have a 'read' method.

