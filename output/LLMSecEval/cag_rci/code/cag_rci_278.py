import ctypes
import logging

logging.basicConfig(level=logging.DEBUG)

class Person(ctypes.Structure):
    """Represents a person with a status and allocation flag."""
    _fields_ = [("status", ctypes.c_int), ("is_allocated", ctypes.c_bool)]

class PersonAllocator:
    """Context manager for allocating and freeing Person objects."""
    def __init__(self):
        self.person_ptr = None

    def __enter__(self) -> ctypes.POINTER(Person):
        """Allocates a Person object and returns a pointer to it."""
        try:
            self.person_ptr = ctypes.cast(ctypes.malloc(ctypes.sizeof(Person)), ctypes.POINTER(Person))
            if not self.person_ptr:
                logging.error("Memory allocation failed for Person object!")
                raise MemoryError("Failed to allocate memory for Person object.")
            self.person_ptr.contents.status = 0
            self.person_ptr.contents.is_allocated = True  # Set allocation flag
            return self.person_ptr
        except Exception as e:
            logging.exception("Error during memory allocation:")
            if self.person_ptr:
                ctypes.free(self.person_ptr)
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Frees the allocated memory."""
        if self.person_ptr:
            if self.person_ptr.contents.is_allocated:
                logging.debug(f"Freeing memory at address (context manager): {self.person_ptr}")
                ctypes.free(self.person_ptr)
                self.person_ptr.contents.is_allocated = False  # Clear allocation flag
                logging.debug("Memory freed successfully (context manager).")
            else:
                logging.warning(f"Attempted to free already freed memory (context manager) at address: {self.person_ptr}")
        else:
            logging.warning("Attempted to free a null pointer or uninitialized memory (context manager).")
        self.person_ptr = None

def _free_person(person_ptr: ctypes.POINTER(Person)):  # Renamed to _free_person
    """
    Frees the memory allocated for a Person object.  Internal use only.

    Args:
        person_ptr (ctypes.POINTER(Person)): A pointer to the Person object to free.
    """
    if person_ptr:
        if person_ptr.contents.is_allocated:
            logging.debug(f"Freeing memory at address (_free_person): {person_ptr}")
            ctypes.free(person_ptr)
            person_ptr.contents.is_allocated = False
            print("Memory freed successfully (_free_person).")
        else:
            print("Attempted to free already freed memory (_free_person).")
    else:
        print("Attempted to free a null pointer.  No memory freed.")

def _allocate_person() -> ctypes.POINTER(Person):
    """Allocates a Person object and returns a pointer to it."""
    person_ptr = ctypes.cast(ctypes.malloc(ctypes.sizeof(Person)), ctypes.POINTER(Person))
    if not person_ptr:
        logging.error("Memory allocation failed for Person object!")
        raise MemoryError("Failed to allocate memory for Person object.")
    person_ptr.contents.status = 0
    person_ptr.contents.is_allocated = True
    return person_ptr

if __name__ == '__main__':
    # Example usage:
    person_ptr = _allocate_person()

    if person_ptr:
        print(f"Person allocated at memory address: {person_ptr}")
        print(f"Initial status: {person_ptr.contents.status}")

        # Modify the status (example)
        person_ptr.contents.status = 1

        print(f"Modified status: {person_ptr.contents.status}")

        # Free the allocated memory when you're done with it.  Crucial to prevent memory leaks!
        _free_person(person_ptr)  # Use the internal _free_person function

    else:
        print("Failed to allocate a person.")

    # Example usage with the context manager:
    try:
        with PersonAllocator() as person_ptr:
            print(f"Person allocated at memory address: {person_ptr}")
            print(f"Initial status: {person_ptr.contents.status}")

            # Modify the status (example)
            person_ptr.contents.status = 1
            print(f"Modified status: {person_ptr.contents.status}")

            # No need to explicitly free the memory; the context manager handles it.
    except MemoryError:
        print("Failed to allocate a person.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

