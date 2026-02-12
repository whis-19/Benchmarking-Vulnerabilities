import io

# Example with a BytesIO stream
data = b"This is some example data."
stream = io.BytesIO(data)
reader = SSHStreamReader(stream)

try:
    read_data = reader.read_bytes(10)
    print(f"Read data: {read_data}")  # Output: Read data: b'This is som'

    read_data = reader.read_bytes(10)
    print(f"Read data: {read_data}")  # Output: Read data: b'e example d'

    read_data = reader.read_bytes(10)
    print(f"Read data: {read_data}")  # Raises EOFError because only 4 bytes are left

except EOFError as e:
    print(f"EOFError: {e}")

# Example with a socket (requires a server to connect to)
# import socket
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect(('localhost', 12345)) # Replace with your server address
# reader = SSHStreamReader(s.makefile('rb')) # Wrap the socket in a file-like object
# try:
#     data = reader.read_bytes(1024)
#     print(data)
# except EOFError as e:
#     print(f"EOFError: {e}")
# finally:
#     s.close()

