import ctypes
import threading

# Define a simple Person structure
class Person(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int)]

# Global lock to protect resource allocation
allocation_lock = threading.Lock()

# Maximum number of allowed allocations (to prevent resource exhaustion)
MAX_ALLOCATIONS = 100  # Adjust as needed

# Counter for allocated resources
allocation_count = 0

def allocate_person() -> ctypes.POINTER(Person):
    """
    Allocates memory for a Person object and initializes its status to 0.

    Returns:
        A pointer to the allocated Person object, or None if allocation fails.
    """
    global allocation_count

    with allocation_lock:
        if allocation_count >= MAX_ALLOCATIONS:
            print("Error: Maximum number of allocations reached.")
            return None  # Prevent further allocation

        try:
            # Allocate memory for a Person object
            person_ptr = ctypes.cast(ctypes.POINTER(Person)(), ctypes.POINTER(Person))
            if not person_ptr:
                raise MemoryError("Failed to allocate memory for Person object.")

            # Initialize the status to 0
            person_ptr.contents.status = 0

            allocation_count += 1
            return person_ptr

        except MemoryError as e:
            print(f"Memory allocation error: {e}")
            # No memory to free here, as allocation failed.
            return None
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            # No memory to free here, as allocation failed.
            return None


def free_person(person_ptr: ctypes.POINTER(Person)):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to free.
    """
    global allocation_count

    with allocation_lock:
        if person_ptr:
            try:
                # No explicit deallocation needed in Python with ctypes.
                # The memory will be garbage collected when the pointer is no longer referenced.
                # However, we decrement the allocation count to track resource usage.
                allocation_count -= 1
                print("Person memory freed.")
            except Exception as e:
                print(f"Error freeing memory: {e}")
        else:
            print("Warning: Attempting to free a null pointer.")


# Example usage:
if __name__ == "__main__":
    person_ptr1 = allocate_person()
    if person_ptr1:
        print(f"Person 1 status: {person_ptr1.contents.status}")  # Output: 0
        person_ptr1.contents.status = 1  # Modify the status
        print(f"Person 1 status after modification: {person_ptr1.contents.status}")  # Output: 1
        free_person(person_ptr1)

    person_ptr2 = allocate_person()
    if person_ptr2:
        print(f"Person 2 status: {person_ptr2.contents.status}")
        free_person(person_ptr2)

    # Attempt to allocate more than the maximum allowed
    for _ in range(MAX_ALLOCATIONS + 1):
        person_ptr = allocate_person()
        if person_ptr:
            print("Allocation successful (should not happen after MAX_ALLOCATIONS)")
            free_person(person_ptr)
        else:
            print("Allocation failed (as expected after MAX_ALLOCATIONS)")
            break

    print(f"Current allocation count: {allocation_count}") # Should be 0 at the end.

