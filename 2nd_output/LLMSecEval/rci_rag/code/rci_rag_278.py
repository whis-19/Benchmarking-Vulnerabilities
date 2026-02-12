import ctypes
import threading
import sys
import logging
from ctypes import malloc, free  # Import malloc and free

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a simple Person structure
class Person(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int), ("magic", ctypes.c_int)]

# Magic number to validate pointers
MAGIC_NUMBER = 0x12345678

# Global lock to protect resource allocation
allocation_lock = threading.Lock()

# Maximum number of allowed allocations (to prevent resource exhaustion)
MAX_ALLOCATIONS = 100
current_allocations = 0

# Maximum size of a single allocation (to prevent large allocations)
PERSON_SIZE = ctypes.sizeof(Person)
MAX_ALLOCATION_SIZE = min(PERSON_SIZE * 2, sys.maxsize)  # Safer overflow prevention


def allocate_person() -> ctypes.POINTER(Person):
    """
    Allocates memory for a Person object, initializes its status to 0, and returns a pointer to it.
    """
    global current_allocations

    with allocation_lock:
        if current_allocations >= MAX_ALLOCATIONS:
            logging.error("Maximum number of allocations reached.")
            return None

        try:
            # Check allocation size before attempting allocation
            if ctypes.sizeof(Person) > MAX_ALLOCATION_SIZE:
                logging.error("Allocation size exceeds maximum allowed.")
                return None

            # Allocate memory using ctypes.malloc
            person_ptr = ctypes.cast(malloc(ctypes.sizeof(Person)), ctypes.POINTER(Person))
            if not person_ptr:
                raise MemoryError("Failed to allocate memory for Person object.")

            # Initialize the status to 0 and set the magic number
            person_ptr.contents.status = 0
            person_ptr.contents.magic = MAGIC_NUMBER

            current_allocations += 1
            logging.info(f"Allocated Person object at {person_ptr}")
            return person_ptr

        except MemoryError as e:
            logging.error(f"Memory allocation error: {e}")
            return None
        except Exception as e:
            logging.exception("An unexpected error occurred during allocation.")
            return None


def free_person(person_ptr: ctypes.POINTER(Person]):
    """
    Frees the memory allocated for a Person object.
    """
    global current_allocations

    with allocation_lock:
        if person_ptr:
            # Validate the pointer using the magic number
            if person_ptr.contents.magic != MAGIC_NUMBER:
                logging.error("Invalid pointer passed to free_person.")
                return

            # Free the memory using ctypes.free
            try:
                free(person_ptr)
                current_allocations -= 1
                logging.info(f"Freed Person object at {person_ptr}")
            except Exception as e:
                logging.error(f"Error freeing memory: {e}")

            # Prevent double free and use-after-free
            # Invalidate the magic number
            # Note: This doesn't prevent use-after-free completely, but it helps detect it.
            try:
                person_ptr.contents.magic = 0
            except ValueError:
                logging.error("Attempted to access freed memory (likely use-after-free).")
        else:
            logging.warning("Attempted to free a null pointer.")


if __name__ == '__main__':
    # Example usage
    person1_ptr = allocate_person()
    if person1_ptr:
        print(f"Person 1 status: {person1_ptr.contents.status}")
        person1_ptr.contents.status = 1
        print(f"Person 1 status after modification: {person1_ptr.contents.status}")
        free_person(person1_ptr)

    person2_ptr = allocate_person()
    if person2_ptr:
        print(f"Person 2 status: {person2_ptr.contents.status}")
        free_person(person2_ptr)

    # Attempt to allocate more than the maximum allowed
    for _ in range(MAX_ALLOCATIONS + 1):
        person_ptr = allocate_person()
        if person_ptr:
            print("Allocated successfully (should not happen after MAX_ALLOCATIONS)")
            free_person(person_ptr)
        else:
            print("Allocation failed (as expected after MAX_ALLOCATIONS)")
            break

    # Demonstrate double free protection
    person3_ptr = allocate_person()
    if person3_ptr:
        free_person(person3_ptr)
        free_person(person3_ptr)  # This will now be caught by the magic number check

    # Demonstrate use-after-free detection (this will likely crash or cause an error)
    person4_ptr = allocate_person()
    if person4_ptr:
        free_person(person4_ptr)
        try:
            print(f"Person 4 status after free: {person4_ptr.contents.status}")  # This is a use-after-free
        except ValueError as e:
            print(f"Caught use-after-free error: {e}")

