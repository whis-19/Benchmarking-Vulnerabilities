import ctypes
import traceback
import contextlib

# Assuming Person is a ctypes Structure defined elsewhere
# Example:
# class Person(ctypes.Structure):
#     _fields_ = [("status", ctypes.c_int)]

MAX_ALLOWED_SIZE = 1024 * 1024  # Example: 1MB maximum size

def allocate_person() -> ctypes.POINTER(Person):
    """
    Allocates memory for a new Person object and initializes the status to 0.

    Returns:
        ctypes.POINTER(Person): A pointer to the newly allocated Person object.

    Raises:
        MemoryError: If memory allocation fails.
        RuntimeError: For unexpected errors during allocation.
    """
    try:
        # Check for potential integer overflow in sizeof(Person)
        person_size = ctypes.sizeof(Person)
        assert person_size > 0 and person_size < MAX_ALLOWED_SIZE, "Person structure is too large"

        # Allocate memory for a Person object using ctypes.malloc.
        person_ptr = ctypes.cast(ctypes.malloc(person_size), ctypes.POINTER(Person))

        # Check if allocation was successful.
        if not person_ptr:
            raise MemoryError("Memory allocation failed.")

        # Initialize the status to 0.
        person_ptr.contents.status = 0

        return person_ptr

    except MemoryError as e:
        print(f"MemoryError during allocation: {e}")  # Log the error
        raise  # Re-raise the MemoryError to force the caller to handle it
    except OSError as e: # Catch OSError specifically
        print(f"OSError during allocation: {e}")
        raise # Re-raise the OSError to force the caller to handle it
    except Exception as e:
        print(f"An unexpected error occurred: {e}") # Log unexpected errors
        traceback.print_exc()  # Print the full traceback
        raise RuntimeError("Unexpected error during Person allocation") from e # Re-raise with context


def free_person(person_ptr: ctypes.POINTER(Person)):
    """Frees the memory allocated for a Person object."""
    if person_ptr:
        ctypes.free(person_ptr)
        #person_ptr = None  # Optional:  Set to None to help detect use-after-free (but doesn't prevent it)

@contextlib.contextmanager
def person_context():
    """Context manager for allocating and freeing a Person object."""
    person_ptr = allocate_person()
    try:
        yield person_ptr
    finally:
        if person_ptr:
            free_person(person_ptr)

# Example Usage:
with person_context() as person:
    if person:
        person.contents.status = 1  # Use the person object
        # ... other operations ...
    else:
        print("Failed to allocate person")
# person_ptr is automatically freed when exiting the 'with' block

