import ctypes
import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)


class Person(ctypes.Structure):
    """
    Represents a person with a name and status.
    """
    _fields_ = [("name", ctypes.c_char_p),
                ("status", ctypes.c_int)]


class SecureBuffer:
    """
    A wrapper around ctypes.create_string_buffer that tracks the size
    and provides secure allocation and deallocation.
    """
    def __init__(self, size: int):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("Size must be a positive integer.")

        # Check for excessively large sizes to prevent denial-of-service
        if size > 2**20:  # 1MB limit - adjust as needed
            raise ValueError("Size exceeds maximum allowed value.")

        self.size = size
        self.buffer = ctypes.create_string_buffer(size)
        self.ptr = ctypes.cast(self.buffer, ctypes.POINTER(ctypes.c_ubyte))
        self._secure_initialize()

    def _secure_initialize(self):
        """Initializes the memory with random data."""
        try:
            random_data = os.urandom(self.size)
            ctypes.memmove(self.ptr, random_data, self.size)
        except OSError as e:
            logging.error(f"Error initializing memory with random data: {e}")
            # Re-raise as MemoryError to be consistent with allocation failures
            raise MemoryError("Failed to initialize memory with random data") from e

    def get_pointer(self) -> ctypes.POINTER(ctypes.c_ubyte):
        return self.ptr

    def secure_free(self):
        """Zeros the memory and invalidates the pointer."""
        if self.ptr:
            try:
                zero_data = b'\x00' * self.size
                ctypes.memmove(self.ptr, zero_data, self.size)
            except ValueError as e:
                logging.error(f"Error zeroing memory: {e}")
                raise  # Re-raise the exception
            finally:
                # Invalidate the pointer to prevent use-after-free
                self.ptr = None
                self.buffer = None  # Help garbage collection


def create_person(name: str) -> Person:
    """
    Creates a new person with the given name and status 0.
    """
    if not isinstance(name, str):
        raise TypeError("Name must be a string.")

    # Input validation: Limit name length to prevent excessive memory allocation
    if len(name) > 255:  # Example limit - adjust as needed
        raise ValueError("Name is too long.")

    person = Person()
    person.status = 0

    name_bytes = name.encode('utf-8')
    name_length = len(name_bytes) + 1  # +1 for null terminator

    # Prevent integer overflow
    if name_length > sys.maxsize:
        raise OverflowError("Name length is too large to allocate memory.")

    try:
        # Use the SecureBuffer class for secure memory management
        secure_buffer = SecureBuffer(name_length)
        name_ptr = secure_buffer.get_pointer()

        # Copy the name into the allocated memory
        ctypes.memmove(name_ptr, name_bytes, len(name_bytes))
        name_ptr[len(name_bytes)] = 0  # Null-terminate the string

        person.name = ctypes.cast(name_ptr, ctypes.c_char_p)  # Assign the pointer to the person's name
        person._secure_buffer = secure_buffer  # Store the SecureBuffer instance

        return person

    except MemoryError as e:
        logging.error(f"Memory allocation failed: {e}")
        raise

    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full traceback
        raise


def free_person(person: Person) -> None:
    """Frees the memory associated with a Person object."""
    if hasattr(person, '_secure_buffer') and person._secure_buffer:
        person._secure_buffer.secure_free()
        person.name = None  # Prevent use-after-free
        del person._secure_buffer


if __name__ == '__main__':
    try:
        person = create_person("Alice")  # Use a variable name
        print(f"Person Name: {person.name.decode('utf-8')}")
        print(f"Person Status: {person.status}")

        free_person(person)

    except MemoryError as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Value Error: {e}")
    except TypeError as e:
        print(f"Type Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

