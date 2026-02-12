import io

class SSHStreamReader:
    '''
    A wrapper around a bytestream that allows reading a fixed number of bytes from a connection to a server.
    '''

    def __init__(self, stream):
        '''
        @param stream:  The stream to read from.
        '''
        if not isinstance(stream, io.BufferedIOBase):
            raise TypeError("Stream must be a BufferedIOBase object (e.g., io.BytesIO, socket.socket)")
        self._stream = stream

    def read_bytes(self, num_bytes: int) -> bytes:
        '''
        Reads a fixed number of bytes from the stream.
        @param num_bytes:  The number of bytes to read.
        @return:    The read bytes.
        @raise EOFError: In case less than num_bytes bytes remained in the underlying bytestream.
        '''
        if not isinstance(num_bytes, int):
            raise TypeError("num_bytes must be an integer")
        if num_bytes < 0:
            raise ValueError("num_bytes must be non-negative")

        # Check if the stream is still open before attempting to read.
        if self._stream.closed:
            raise EOFError("Stream is closed.")

        try:
            data = self._stream.read(num_bytes)
        except Exception as e:
            # Handle potential stream errors (e.g., socket errors)
            raise IOError(f"Error reading from stream: {e}") from e

        if len(data) < num_bytes:
            raise EOFError(f"Expected {num_bytes} bytes, but only received {len(data)} bytes.")

        return data

