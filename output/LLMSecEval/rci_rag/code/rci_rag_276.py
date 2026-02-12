import ctypes
import threading
import logging
import gc  # Import the garbage collection module
import time
import weakref

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the structure for a person
class Person(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int)]  # Consider validating this field if influenced by external input

# Global lock to protect resource allocation
allocation_lock = threading.Lock()

# Maximum number of allowed allocations (to prevent resource exhaustion)
MAX_ALLOCATIONS = 100  # Adjust as needed

# Counter for allocated resources
allocation_count = 0

# Rate limiting parameters (example)
ALLOCATION_WINDOW = 60  # seconds
MAX_ALLOCATIONS_PER_WINDOW = 10
user_allocation_timestamps = {}  # Dictionary to store timestamps per user

# Track allocated pointers for cleanup on exit
allocated_pointers = []
# Use a weak value dictionary to track allocated objects without preventing garbage collection
allocated_persons = weakref.WeakValueDictionary()


def is_rate_limited(user_id):
    """Checks if the allocation rate exceeds the limit for a specific user."""
    global user_allocation_timestamps

    now = time.time()

    if user_id not in user_allocation_timestamps:
        user_allocation_timestamps[user_id] = []

    # Remove timestamps older than the window
    user_allocation_timestamps[user_id] = [t for t in user_allocation_timestamps[user_id] if t > now - ALLOCATION_WINDOW]

    if len(user_allocation_timestamps[user_id]) >= MAX_ALLOCATIONS_PER_WINDOW:
        logging.warning(f"Allocation rate limit exceeded for user {user_id}.")
        return True
    return False


def allocate_person(user_id) -> ctypes.POINTER(Person):
    """
    Allocates memory for a Person object, initializes the status to 0,
    and returns a pointer to the allocated memory.  Includes resource
    management and security considerations.

    Returns:
        ctypes.POINTER(Person): A pointer to the allocated Person object,
                                 or None if allocation fails.
    """
    global allocation_count, allocated_pointers

    with allocation_lock:  # Protect allocation with a lock
        if is_rate_limited(user_id):
            return None

        if allocation_count >= MAX_ALLOCATIONS:
            logging.error("Maximum number of allocations reached.")
            return None  # Prevent further allocation

        try:
            # Allocate memory using ctypes
            person_ptr = ctypes.cast(ctypes.POINTER(Person)(), ctypes.POINTER(Person))
            if not person_ptr:
                raise MemoryError("ctypes.cast failed to allocate memory for Person object.")

            # Initialize the status field
            person_ptr.contents.status = 0

            allocation_count += 1
            if user_id not in user_allocation_timestamps:
                user_allocation_timestamps[user_id] = []
            user_allocation_timestamps[user_id].append(time.time())  # Record allocation time
            logging.info(f"Allocated person for user {user_id}. Total allocations: {allocation_count}")

            allocated_pointers.append(person_ptr)  # Track the allocated pointer
            allocated_persons[id(person_ptr)] = person_ptr # Track the allocated object

            return person_ptr

        except MemoryError as e:
            logging.error(f"Memory allocation error: {e}")
            # No memory to free here, as allocation failed.
            return None
        except Exception as e:
            logging.exception("An unexpected error occurred during allocation:")
            # No memory to free here, as allocation failed.
            return None


def free_person(person_ptr: ctypes.POINTER(Person]):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to free.
    """
    global allocation_count, allocated_pointers

    with allocation_lock:
        if person_ptr:
            try:
                # No explicit deallocation needed with ctypes.  The pointer
                # will be garbage collected when it goes out of scope.
                # However, we decrement the allocation count.
                allocation_count -= 1
                logging.info(f"Freed person. Total allocations: {allocation_count}")

                # Remove the pointer from the list of allocated pointers
                if person_ptr in allocated_pointers:
                    allocated_pointers.remove(person_ptr)

                # Remove the object from the weak value dictionary
                if id(person_ptr) in allocated_persons:
                    del allocated_persons[id(person_ptr)]

            except Exception as e:
                logging.exception("Error freeing memory:")
                # Consider whether to trigger a system alert here, as allocation_count is now inconsistent.
                # It might be better to log the error and attempt to recover gracefully,
                # as raising an exception could lead to further instability.
                # Perhaps a separate monitoring thread could check for inconsistencies in `allocation_count`
                # and take corrective action.
        else:
            logging.warning("Attempting to free a null pointer.")


class PersonAllocator:
    """Context manager for allocating and freeing Person objects."""
    def __init__(self, user_id):
        self.person_ptr = None
        self.user_id = user_id

    def __enter__(self):
        self.person_ptr = allocate_person(self.user_id)
        if self.person_ptr is None:
            raise MemoryError("Failed to allocate person")
        return self.person_ptr

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.person_ptr:
            free_person(self.person_ptr)
            self.person_ptr = None  # Prevent accidental reuse of the pointer


# Example usage:
if __name__ == "__main__":
    # Example using the context manager
    user1_id = "user1"
    user2_id = "user2"

    try:
        with PersonAllocator(user1_id) as person_ptr:
            logging.info(f"Person status: {person_ptr.contents.status}")  # Access the status
            person_ptr.contents.status = 1  # Update the status
            logging.info(f"Person updated status: {person_ptr.contents.status}")
    except MemoryError as e:
        logging.error(f"Error: {e}")

    # Example of exceeding the maximum allocations (global limit)
    for i in range(MAX_ALLOCATIONS + 1):
        person_ptr = allocate_person("test_user")
        if person_ptr:
            logging.info(f"Allocated person {i+1}.")
        else:
            logging.warning(f"Failed to allocate a person {i+1} (likely due to max allocations or rate limiting).")
            break

    # Example of triggering garbage collection (use sparingly)
    gc.collect()
    logging.info("Garbage collection triggered.")
    # Note: ctypes doesn't trigger garbage collection directly.
    # Memory might not be immediately freed.

    # Example of rate limiting (per user)
    logging.info("Testing rate limiting...")
    for i in range(MAX_ALLOCATIONS_PER_WINDOW + 5):
        person_ptr_user1 = allocate_person(user1_id)
        if person_ptr_user1:
            logging.info(f"Allocated person {i+1} for {user1_id} (rate limiting test).")
        else:
            logging.warning(f"Failed to allocate a person {i+1} for {user1_id} (rate limiting test).")

        person_ptr_user2 = allocate_person(user2_id)
        if person_ptr_user2:
            logging.info(f"Allocated person {i+1} for {user2_id} (rate limiting test).")
        else:
            logging.warning(f"Failed to allocate a person {i+1} for {user2_id} (rate limiting test).")
        time.sleep(0.1)  # Simulate rapid allocations

    # Potential for memory fragmentation exists, especially in long-running applications.
    # Consider using memory pools or other custom allocation strategies for improved memory management.

    # Explicitly free all allocated resources before exiting
    logging.info("Cleaning up allocated resources...")
    for ptr in list(allocated_pointers): # Iterate over a copy to allow modification
        free_person(ptr)

    logging.info(f"Total allocations after cleanup: {allocation_count}")
    logging.info("Exiting.")

