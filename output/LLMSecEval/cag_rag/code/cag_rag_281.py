import sys
import os

def allocate_and_copy_stdin():
    """
    Allocates two buffers, reads 100 characters from stdin into each,
    and handles potential errors securely.
    """

    buf = None
    buf1 = None

    try:
        # Allocate the first buffer
        buf_size = 1024
        buf = bytearray(buf_size)  # Use bytearray for mutable buffer
        
        # Read from stdin into the first buffer
        input_data = sys.stdin.buffer.read(100)  # Read up to 100 bytes
        
        # Validate input length
        if len(input_data) > buf_size:
            raise ValueError("Input data exceeds buffer size.")

        # Copy data into the buffer, handling potential buffer overflows
        buf[:len(input_data)] = input_data
        
        # Fill the rest of the buffer with null bytes (optional, but good practice)
        buf[len(input_data):] = b'\0' * (buf_size - len(input_data))

        # Allocate the second buffer
        buf1_size = 1024
        buf1 = bytearray(buf1_size)

        # Read from stdin into the second buffer
        input_data1 = sys.stdin.buffer.read(100)  # Read up to 100 bytes

        # Validate input length
        if len(input_data1) > buf1_size:
            raise ValueError("Input data exceeds buffer size.")

        # Copy data into the buffer, handling potential buffer overflows
        buf1[:len(input_data1)] = input_data1

        # Fill the rest of the buffer with null bytes (optional, but good practice)
        buf1[len(input_data1):] = b'\0' * (buf1_size - len(input_data1))

        # Process the buffers (example: print the contents)
        print("Buffer 1:", buf.decode('utf-8', errors='ignore').rstrip('\0')) # Decode and remove trailing nulls
        print("Buffer 2:", buf1.decode('utf-8', errors='ignore').rstrip('\0'))

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # No explicit memory deallocation needed in Python with garbage collection.
        # However, if you were using a C extension or a library that requires
        # explicit memory management, you would release the memory here.
        # Example (hypothetical):
        # if buf is not None:
        #     free(buf)  # Assuming 'free' is a function from a C extension
        # if buf1 is not None:
        #     free(buf1)
        pass

if __name__ == "__main__":
    allocate_and_copy_stdin()

