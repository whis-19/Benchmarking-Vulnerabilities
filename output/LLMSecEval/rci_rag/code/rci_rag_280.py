import ctypes
import os
import sys

# Define a maximum allocation size to prevent excessive memory usage
MAX_ALLOCATION_SIZE = 1024 * 1024  # 1MB limit

# Define a maximum number of allocations to prevent resource exhaustion
MAX_ALLOCATIONS = 100

# Keep track of the number of allocations
allocation_count = 0

# Define a simple structure for a person
class Person(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int)]

# Function to allocate memory for a person and set the status to 0
def allocate_person():
    """
    Allocates memory for a Person object and initializes its status to 0.

    Returns:
        A pointer to the allocated Person object, or None if allocation fails.
    """
    global allocation_count

    # Check if the maximum number of allocations has been reached
    if allocation_count >= MAX_ALLOCATIONS:
        print("Error: Maximum number of allocations reached.")
        return None

    # Check if the requested size exceeds the maximum allowed size
    size = ctypes.sizeof(Person)
    if size > MAX_ALLOCATION_SIZE:
        print("Error: Requested allocation size exceeds the maximum allowed size.")
        return None

    try:
        # Allocate memory using ctypes
        person_ptr = ctypes.cast(ctypes.create_string_buffer(size), ctypes.POINTER(Person))

        # Initialize the status to 0
        person_ptr.contents.status = 0

        # Increment the allocation count
        allocation_count += 1

        return person_ptr

    except MemoryError as e:
        print(f"Error: Memory allocation failed (likely due to insufficient system memory): {e}")
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred during allocation: {e}")
        return None

# Function to free the allocated memory
def free_person(person_ptr):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to be freed.
    """
    global allocation_count

    if person_ptr:
        try:
            # No explicit free needed with ctypes create_string_buffer.  It's managed by Python's garbage collection.
            # However, we decrement the allocation count to track resources.
            allocation_count -= 1
            print("Memory freed successfully.")
        except TypeError as e:
            print(f"Error: Invalid pointer type: {e}")
        except Exception as e:
            print(f"Error: An unexpected error occurred while freeing memory: {e}")
    else:
        print("Warning: Attempted to free a null pointer.")


if __name__ == "__main__":
    # Allocate a person
    person_ptr = allocate_person()

    if person_ptr:
        print(f"Person allocated at address: {person_ptr}")
        print(f"Initial status: {person_ptr.contents.status}")

        # Modify the status
        person_ptr.contents.status = 1

        print(f"Modified status: {person_ptr.contents.status}")

        # Free the memory
        free_person(person_ptr)
        person_ptr = None  # Important: Set to None after freeing
    else:
        print("Failed to allocate person.")

    # Now, if you try to access person_ptr, you'll get an error:
    try:
        if person_ptr:  # Check if person_ptr is not None before accessing
            print(person_ptr.contents.status)  # This will raise an AttributeError
    except AttributeError:
        print("Error: Attempted to access freed memory.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Attempt to allocate more than the maximum number of allocations
    for _ in range(MAX_ALLOCATIONS + 1):
        ptr = allocate_person()
        if ptr is None:
            break  # Stop if allocation fails

    print(f"Current allocation count: {allocation_count}")

