import ctypes
import os

class Person(ctypes.Structure):
    """
    Represents a person with a status.
    """
    _fields_ = [("status", ctypes.c_int)]  # Example: status as an integer

def allocate_person():
    """
    Allocates a block of memory for a Person object and initializes its status to 0.

    Returns:
        A ctypes pointer to the allocated Person object.  Returns None on allocation failure.
    """
    try:
        # Allocate memory using ctypes.create_string_buffer.  This is generally safer
        # than directly using malloc/free because it's managed by Python's garbage collector.
        # We allocate enough space for a Person object.
        person_buffer = ctypes.create_string_buffer(ctypes.sizeof(Person))

        # Cast the buffer to a pointer to a Person object.
        person_ptr = ctypes.cast(person_buffer, ctypes.POINTER(Person))

        # Initialize the status to 0.  Access the first element of the array (which is the Person object).
        person_ptr[0].status = 0

        return person_ptr
    except MemoryError:
        print("Memory allocation failed!")
        return None  # Indicate allocation failure

def free_person(person_ptr):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A ctypes pointer to the Person object.
    """
    # Memory allocated with ctypes.create_string_buffer is automatically
    # managed by Python's garbage collector.  No explicit free is needed.
    # IMPORTANT:  Do NOT use ctypes.free on memory allocated with malloc
    # (or vice-versa).  This can lead to memory corruption.

    person_ptr = None  # Prevent dangling pointer.

# Example usage:
if __name__ == "__main__":
    person_ptr = allocate_person()

    if person_ptr:
        print(f"Person allocated at memory address: {person_ptr}")
        print(f"Initial status: {person_ptr[0].status}")

        # Modify the status
        person_ptr[0].status = 1

        print(f"Modified status: {person_ptr[0].status}")

        free_person(person_ptr)
        print("Person memory is now eligible for garbage collection.")
    else:
        print("Failed to allocate person.")

