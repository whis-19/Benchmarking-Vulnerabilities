import ctypes

class Person(ctypes.Structure):
    """
    Represents a person with a status.
    """
    _fields_ = [("status", ctypes.c_int)]  # Example: status as an integer

def allocate_person():
    """
    Allocates a block of memory for a Person object and initializes the status to 0.

    Returns:
        A pointer to the allocated Person object.  Returns None on allocation failure.
    """
    try:
        # Allocate memory for a Person object
        person_ptr = ctypes.cast(ctypes.create_string_buffer(ctypes.sizeof(Person)), ctypes.POINTER(Person))

        # Check if allocation was successful (important!)
        if not person_ptr:
            print("Memory allocation failed!")  # Log the error
            return None

        # Initialize the status to 0
        person_ptr.contents.status = 0

        return person_ptr

    except MemoryError:
        print("Out of memory!")  # Handle potential out-of-memory errors
        return None
    except Exception as e:
        print(f"An error occurred during memory allocation: {e}")
        return None


def free_person(person_ptr):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to be freed.
    """
    if person_ptr:
        # No explicit free needed with ctypes create_string_buffer.
        # The memory is managed by the buffer.
        # However, if you used a different allocation method (e.g., malloc),
        # you would need to use ctypes.free(person_ptr) here.
        pass  # No-op for this example
    else:
        print("Warning: Attempting to free a null pointer.")


if __name__ == '__main__':
    # Example usage:
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

