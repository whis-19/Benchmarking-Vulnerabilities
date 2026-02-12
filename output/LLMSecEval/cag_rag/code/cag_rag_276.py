import ctypes
import os

# Define a structure for the person
class Person(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int)]

# Define a maximum number of allowed allocations to prevent resource exhaustion
MAX_ALLOCATIONS = 100  # Adjust this value based on your system's resources

# Keep track of the number of allocations
allocation_count = 0

# A list to store allocated memory blocks for later cleanup (if needed)
allocated_blocks = []

def allocate_person() -> ctypes.POINTER(Person):
    """
    Allocates a block of memory for a Person object, sets the status to 0,
    and returns a pointer to the beginning of the block.

    Raises:
        MemoryError: If memory allocation fails or the maximum number of allocations is reached.

    Returns:
        ctypes.POINTER(Person): A pointer to the allocated Person object.  Returns None on failure.
    """
    global allocation_count
    global allocated_blocks

    # Check if the maximum number of allocations has been reached
    if allocation_count >= MAX_ALLOCATIONS:
        print("Error: Maximum number of allocations reached.")
        raise MemoryError("Maximum number of allocations reached.")

    try:
        # Allocate memory for a Person object
        person_ptr = ctypes.cast(ctypes.create_string_buffer(ctypes.sizeof(Person)), ctypes.POINTER(Person))

        if not person_ptr:
            raise MemoryError("Failed to allocate memory for Person object.")

        # Initialize the status field to 0
        person_ptr.contents.status = 0

        # Increment the allocation count
        allocation_count += 1

        # Add the allocated block to the list for potential later cleanup
        allocated_blocks.append(person_ptr)

        return person_ptr

    except MemoryError as e:
        print(f"Memory allocation error: {e}")
        # Attempt to release any partially allocated resources (if applicable)
        # In this simple case, there's nothing to release if allocation fails.
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Handle other potential errors and release resources if necessary.
        return None


def free_person(person_ptr: ctypes.POINTER(Person)):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to be freed.
    """
    global allocation_count
    global allocated_blocks

    if person_ptr in allocated_blocks:
        # Remove the pointer from the list of allocated blocks
        allocated_blocks.remove(person_ptr)

        # Decrement the allocation count
        allocation_count -= 1

        # No explicit free is needed in Python when using ctypes.create_string_buffer.
        # The memory is managed by Python's garbage collector.
        # However, removing it from allocated_blocks prevents double "freeing"
        # if this function is called multiple times with the same pointer.

        print("Memory freed successfully.")
    else:
        print("Warning: Attempted to free memory that was not allocated or already freed.")


def cleanup_all_allocations():
    """
    Frees all allocated memory blocks.  This is useful for cleaning up
    resources when the program exits or encounters a critical error.
    """
    global allocated_blocks
    while allocated_blocks:
        person_ptr = allocated_blocks.pop()
        free_person(person_ptr)  # Use the existing free_person function

# Example usage:
if __name__ == "__main__":
    try:
        person1_ptr = allocate_person()
        if person1_ptr:
            print(f"Person 1 status: {person1_ptr.contents.status}")  # Output: Person 1 status: 0
            person1_ptr.contents.status = 1  # Modify the status
            print(f"Person 1 status after modification: {person1_ptr.contents.status}") # Output: Person 1 status after modification: 1
            free_person(person1_ptr)

        person2_ptr = allocate_person()
        if person2_ptr:
            print(f"Person 2 status: {person2_ptr.contents.status}")
            free_person(person2_ptr)

        # Simulate reaching the maximum number of allocations
        for _ in range(MAX_ALLOCATIONS - 2):  # Allocate up to the limit
            temp_ptr = allocate_person()
            if temp_ptr:
                free_person(temp_ptr)

        # Attempt to allocate one more time (should raise MemoryError)
        try:
            person_overflow_ptr = allocate_person()
        except MemoryError as e:
            print(f"Caught expected MemoryError: {e}")
        else:
            if person_overflow_ptr:
                free_person(person_overflow_ptr)
                print("Error: MemoryError was not raised when it should have been.")

    except Exception as e:
        print(f"An error occurred during the example: {e}")
    finally:
        # Ensure all allocated memory is freed, even if an error occurs
        cleanup_all_allocations()

