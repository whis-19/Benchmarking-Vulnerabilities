import ctypes
import os

# Define the structure for a person
class Person(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int)]

# Define a maximum allocation size to prevent excessive memory usage
MAX_ALLOCATION_SIZE = 1024 * 1024  # 1MB limit

# Define a maximum number of allocations to prevent resource exhaustion
MAX_ALLOCATIONS = 100

# Keep track of the number of allocations
allocation_count = 0

# Function to allocate memory for a person and set the status to 0
def allocate_person():
    """
    Allocates memory for a Person object, sets the status field to 0,
    and returns a pointer to the allocated memory.

    Raises:
        MemoryError: If memory allocation fails or if allocation limits are exceeded.

    Returns:
        ctypes.POINTER(Person): A pointer to the allocated Person object.
    """
    global allocation_count

    # Check if the maximum number of allocations has been reached
    if allocation_count >= MAX_ALLOCATIONS:
        raise MemoryError("Maximum number of allocations reached.")

    # Check if the requested allocation size exceeds the maximum allowed size
    person_size = ctypes.sizeof(Person)
    if person_size > MAX_ALLOCATION_SIZE:
        raise MemoryError("Requested allocation size exceeds the maximum allowed size.")

    try:
        # Allocate memory using ctypes
        person_ptr = ctypes.cast(ctypes.create_string_buffer(person_size), ctypes.POINTER(Person))

        # Initialize the status field to 0
        person_ptr.contents.status = 0

        # Increment the allocation count
        allocation_count += 1

        return person_ptr

    except MemoryError as e:
        # Handle memory allocation errors
        print(f"Memory allocation failed: {e}")
        raise  # Re-raise the exception to signal failure to the caller

# Function to free the allocated memory
def free_person(person_ptr):
    """
    Frees the memory pointed to by the given pointer.

    Args:
        person_ptr (ctypes.POINTER(Person)): A pointer to the allocated Person object.
    """
    global allocation_count

    if person_ptr:
        # No explicit free is needed with ctypes.create_string_buffer.
        # The memory is managed by the string buffer.
        # However, we decrement the allocation count to track resource usage.
        allocation_count -= 1
        person_ptr = None  # Set the pointer to None to prevent double freeing
    else:
        print("Warning: Attempting to free a null pointer.")


if __name__ == '__main__':
    try:
        # Allocate memory for a person
        person_ptr = allocate_person()

        if person_ptr:
            print(f"Person allocated at address: {person_ptr}")
            print(f"Initial status: {person_ptr.contents.status}")

            # Modify the status (example)
            person_ptr.contents.status = 1

            print(f"Modified status: {person_ptr.contents.status}")

            # Free the allocated memory
            free_person(person_ptr)
            print("Person memory freed.")

        else:
            print("Failed to allocate memory for a person.")

    except MemoryError as e:
        print(f"An error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

