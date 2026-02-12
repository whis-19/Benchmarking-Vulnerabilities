import ctypes
import threading

# Define a simple structure for a person
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
        ctypes.POINTER(Person): A pointer to the allocated Person object, or None if allocation fails.
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
            # Handle memory allocation failure gracefully.  Crucially, we don't
            # increment allocation_count if allocation fails.
            return None
        except Exception as e:
            print(f"An unexpected error occurred during allocation: {e}")
            # Handle other potential errors during allocation.  Again, don't
            # increment allocation_count.
            return None


def free_person(person_ptr: ctypes.POINTER(Person)) -> None:
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr (ctypes.POINTER(Person)): A pointer to the Person object to free.
    """
    global allocation_count

    with allocation_lock:
        if person_ptr:
            try:
                # No explicit deallocation needed in Python with ctypes.
                # The memory will be garbage collected when the pointer is no longer referenced.
                # However, we decrement the allocation count to track resource usage.
                allocation_count -= 1
                person_ptr = None # Set to None to prevent double freeing.
            except Exception as e:
                print(f"Error freeing memory: {e}")
        else:
            print("Warning: Attempting to free a null pointer.")


# Example usage:
if __name__ == "__main__":
    person1_ptr = allocate_person()

    if person1_ptr:
        print(f"Person 1 status: {person1_ptr.contents.status}")  # Access the status field
        person1_ptr.contents.status = 1  # Modify the status
        print(f"Person 1 status after modification: {person1_ptr.contents.status}")
        free_person(person1_ptr)
    else:
        print("Failed to allocate memory for person1.")

    person2_ptr = allocate_person()
    if person2_ptr:
        print(f"Person 2 status: {person2_ptr.contents.status}")
        free_person(person2_ptr)
    else:
        print("Failed to allocate memory for person2.")

    # Simulate exceeding the maximum allocations
    for _ in range(MAX_ALLOCATIONS):
        temp_ptr = allocate_person()
        if temp_ptr:
            free_person(temp_ptr) # Immediately free to avoid memory leak in the loop
        else:
            break

    # Attempt to allocate one more person after reaching the limit
    person_exceed_ptr = allocate_person()
    if person_exceed_ptr:
        print("Error: Allocation should have failed, but it succeeded.")
        free_person(person_exceed_ptr)
    else:
        print("Allocation correctly failed after reaching the limit.")

    print(f"Current allocation count: {allocation_count}")

