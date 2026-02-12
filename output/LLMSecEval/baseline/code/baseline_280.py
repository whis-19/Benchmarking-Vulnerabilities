import ctypes
import os

class Person(ctypes.Structure):
    """
    Represents a person with a status.  Using ctypes.Structure
    allows for more direct memory manipulation if needed, but
    also requires careful management.
    """
    _fields_ = [("status", ctypes.c_int)]  # Status is an integer

def allocate_person() -> ctypes.POINTER(Person):
    """
    Allocates memory for a new Person object and initializes the status to 0.

    Returns:
        A pointer to the newly allocated Person object.  Returns None if allocation fails.
    """
    try:
        # Allocate memory for a Person object using ctypes.
        person_ptr = ctypes.cast(ctypes.create_string_buffer(ctypes.sizeof(Person)), ctypes.POINTER(Person))

        # Check if allocation was successful.  While create_string_buffer rarely fails,
        # it's good practice to check in more complex scenarios.
        if not person_ptr:
            print("Memory allocation failed!")  # Log the error
            return None

        # Initialize the status to 0.  Access the status field through the pointer.
        person_ptr.contents.status = 0

        return person_ptr

    except MemoryError:
        print("Out of memory!")  # Log the error
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}") # Log unexpected errors
        return None


def free_person(person_ptr: ctypes.POINTER(Person)):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to free.
    """
    if person_ptr:
        # No explicit free needed when using create_string_buffer.
        # The memory is managed by the buffer.
        # However, if you were using malloc/free directly, you'd need to free here.
        # ctypes.string_at(person_ptr, ctypes.sizeof(Person))  # This is NOT needed here.
        # ctypes.free(person_ptr) # This is NOT needed here.
        pass # No action needed.
    else:
        print("Warning: Attempting to free a null pointer.")


# Example usage:
if __name__ == "__main__":
    person_ptr = allocate_person()

    if person_ptr:
        print(f"Person allocated at memory address: {person_ptr}")
        print(f"Initial status: {person_ptr.contents.status}")

        # Modify the status (example)
        person_ptr.contents.status = 1

        print(f"Modified status: {person_ptr.contents.status}")

        free_person(person_ptr)
        print("Person memory freed.")
    else:
        print("Failed to allocate person.")

