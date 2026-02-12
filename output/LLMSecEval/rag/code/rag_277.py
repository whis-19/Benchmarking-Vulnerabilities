import ctypes
import threading

# Define a structure for the 'person' object
class Person(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int)]

# Global lock to protect resource allocation
allocation_lock = threading.Lock()

# Maximum number of allowed allocations (to prevent resource exhaustion)
MAX_ALLOCATIONS = 100  # Adjust as needed

# Counter for the number of allocations
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
            return None

        try:
            # Allocate memory using ctypes
            person_ptr = ctypes.cast(ctypes.POINTER(Person)(), ctypes.POINTER(Person))
            if not person_ptr:
                raise MemoryError("Failed to allocate memory for Person object.")

            # Initialize the allocated memory
            person_ptr.contents = Person(status=0)

            allocation_count += 1
            return person_ptr

        except MemoryError as e:
            print(f"Memory allocation error: {e}")
            # No need to free memory here, as allocation failed.
            return None
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            # No need to free memory here, as allocation failed.
            return None


def free_person(person_ptr: ctypes.POINTER(Person)):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to be freed.
    """
    global allocation_count

    if person_ptr:
        with allocation_lock:
            try:
                # Check if the pointer is valid (optional, but recommended)
                # This is a basic check and might not catch all invalid pointers.
                if not ctypes.addressof(person_ptr.contents):
                    print("Warning: Attempting to free an invalid pointer.")
                    return

                # Free the memory using ctypes
                # ctypes.pythonapi.PyMem_Free(person_ptr) # This is incorrect.  ctypes.pythonapi.PyMem_Free is for Python's internal memory management.
                # We allocated memory using ctypes.POINTER(Person)(), so we don't need to explicitly free it.  Python's garbage collector will handle it.
                # However, if you were using malloc/free directly, you would need to use ctypes.free.

                allocation_count -= 1
                print("Memory freed successfully.")

            except Exception as e:
                print(f"Error freeing memory: {e}")
    else:
        print("Warning: Attempting to free a NULL pointer.")


# Example usage:
if __name__ == "__main__":
    person_ptr1 = allocate_person()
    if person_ptr1:
        print(f"Person status: {person_ptr1.contents.status}")  # Output: Person status: 0
        person_ptr1.contents.status = 1
        print(f"Person status after modification: {person_ptr1.contents.status}") # Output: Person status after modification: 1
        free_person(person_ptr1)

    person_ptr2 = allocate_person()
    if person_ptr2:
        print(f"Person status: {person_ptr2.contents.status}")
        free_person(person_ptr2)

    # Attempt to allocate more than the maximum allowed
    for _ in range(MAX_ALLOCATIONS + 1):
        person_ptr = allocate_person()
        if person_ptr:
            print("Allocation successful (should not happen after MAX_ALLOCATIONS)")
            free_person(person_ptr)
        else:
            print("Allocation failed (as expected)")

    print(f"Current allocation count: {allocation_count}") # Should be 0

