import ctypes
import sys

class Person(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int)]

class PersonContext:
    def __enter__(self):
        self.person_ptr = ctypes.cast(ctypes.malloc(ctypes.sizeof(Person)), ctypes.POINTER(Person))
        if not self.person_ptr:
            raise MemoryError("Failed to allocate Person")
        self.person_ptr.contents.status = 0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.person_ptr:
            ctypes.free(self.person_ptr)
            print("Memory freed successfully.")
            self.person_ptr = None  # Prevent double free and use-after-free
            assert self.person_ptr is None, "Person pointer should be None after free" # Add assertion

    def get_status(self):
        if self.person_ptr:
            return self.person_ptr.contents.status
        else:
            raise ValueError("Person object has been freed.")

    def set_status(self, new_status: int):
        """Sets the status of a person, validating the input."""
        if not self.person_ptr:
            raise ValueError("Person object has been freed.")

        min_int = -2**(ctypes.sizeof(ctypes.c_int) * 8 - 1)
        max_int = 2**(ctypes.sizeof(ctypes.c_int) * 8 - 1) - 1

        if not (min_int <= new_status <= max_int):
            raise ValueError(f"Status value {new_status} is out of range for ctypes.c_int (min: {min_int}, max: {max_int})")

        self.person_ptr.contents.status = new_status


if __name__ == '__main__':
    try:
        with PersonContext() as context:
            person_ptr = context.person_ptr # Get the pointer for set_status
            print(f"Person allocated at memory address: {person_ptr}")
            print(f"Initial status: {context.get_status()}")

            try:
                context.set_status(100)  # Valid status
                print(f"Status set to: {context.get_status()}")

                context.set_status(sys.maxsize) # Intentionally cause overflow
            except ValueError as e:
                print(f"Error setting status: {e}")

        # Memory is automatically freed here
    except MemoryError as e:
        print(f"Error: {e}")
    except OSError as e:  # Catch potential OS errors during memory allocation/free
        print(f"OS Error: {e}")
    except TypeError as e: # Catch potential type errors
        print(f"Type Error: {e}")
    except ValueError as e: # Catch potential value errors
        print(f"Value Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

