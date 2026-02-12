import ctypes
import threading

# Define the structure for a person
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
            person_ptr.contents = Person(status=0)  # Initialize status

            allocation_count += 1
            return person_ptr

        except MemoryError as e:
            print(f"Memory allocation error: {e}")
            # System is in a safe posture because no memory was successfully allocated.
            return None
        except Exception as e:
            print(f"An unexpected error occurred during allocation: {e}")
            # System is in a safe posture because no memory was successfully allocated.
            return None


def free_person(person_ptr: ctypes.POINTER(Person)) -> None:
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to free.
    """
    global allocation_count

    with allocation_lock:
        if person_ptr:  # Check if the pointer is valid
            try:
                # No explicit free needed in Python with ctypes.  The garbage collector will handle it.
                # However, we need to decrement the allocation count.
                allocation_count -= 1
                person_ptr = None # Set to None to prevent double freeing.
            except Exception as e:
                print(f"Error freeing memory: {e}")
        else:
            print("Warning: Attempted to free a null pointer.")


# Example usage:
if __name__ == "__main__":
    person1_ptr = allocate_person()

    if person1_ptr:
        print(f"Person status: {person1_ptr.contents.status}")  # Access the status
        person1_ptr.contents.status = 1  # Modify the status
        print(f"Modified person status: {person1_ptr.contents.status}")

        free_person(person1_ptr)
    else:
        print("Failed to allocate memory for person1.")

    # Example of exceeding the allocation limit
    for _ in range(MAX_ALLOCATIONS + 1):
        person_ptr = allocate_person()
        if person_ptr:
            print("Allocated a person.")
            free_person(person_ptr) # Free immediately to avoid memory leak in this example
        else:
            print("Failed to allocate a person (allocation limit reached).")
            break

