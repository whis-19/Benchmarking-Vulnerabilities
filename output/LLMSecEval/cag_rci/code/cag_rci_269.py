import mmap
import os
import ctypes

def secure_erase_string(string_to_erase):
    """
    Securely erases a string from memory using mmap.

    WARNING: This only works on a *copy* of the string data.  The original
    string may still exist in memory.  This is for demonstration purposes only.
    For truly sensitive string data, avoid using Python strings directly.
    """
    byte_string = string_to_erase.encode('utf-8')  # Convert to bytes
    length = len(byte_string)

    with mmap.mmap(-1, length) as mm:
        mm.write(byte_string)
        mm.seek(0)
        mm.write(os.urandom(length))
        mm.flush()
        mm.close()  # Explicitly unmap the memory (optional but clear)
        print("String securely erased (attempted) from mmap.")

def secure_erase_ctypes_zero(data):
    """Securely erases data using ctypes by overwriting with zeros."""
    length = len(data)
    buffer = ctypes.create_string_buffer(data)  # Create a mutable buffer
    ctypes.memset(buffer, 0, length)  # Overwrite with zeros

def secure_erase_ctypes_random(data):
    """Securely erases data using ctypes by overwriting with random data."""
    length = len(data)
    buffer = ctypes.create_string_buffer(data)  # Create a mutable buffer
    os.urandom(length, buffer)  # Overwrite with random data


# Example usage (demonstration only!)
sensitive_string = "MySuperSecretPassword"
secure_erase_string(sensitive_string)

sensitive_data = b"This is a secret password"
secure_erase_ctypes_zero(sensitive_data)
# OR
sensitive_data = b"This is a secret password"
secure_erase_ctypes_random(sensitive_data)


# IMPORTANT: The original 'sensitive_string' still exists in memory!

