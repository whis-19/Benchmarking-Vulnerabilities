import ctypes
import sys

class Person(ctypes.Structure):
    """
    Represents a person with a status.
    """
    _fields_ = [("status", ctypes.c_int)]  # Example: status as an integer

def allocate_person():
    """
    Allocates a block of memory for a Person object and initializes the status to 0.

    Returns:
        A pointer to the allocated Person object.  Raises an exception on allocation failure.
    Raises:
        MemoryError: If memory allocation fails.
        OSError: If there's an operating system error during allocation.
    """
    try:
        # Allocate memory for a Person object
        person_ptr = ctypes.cast(ctypes.create_string_buffer(ctypes.sizeof(Person)), ctypes.POINTER(Person))

        # Check if allocation was successful (important!)
        if not person_ptr:
            raise MemoryError("Memory allocation failed!")

        # Initialize the status to 0
        person_ptr.contents.status = 0

        return person_ptr

    except MemoryError as e:
        print(f"Out of memory: {e}", file=sys.stderr)
        raise  # Re-raise the exception to force the caller to handle it
    except OSError as e:
        print(f"Operating system error during allocation: {e}", file=sys.stderr)
        raise # Re-raise the exception
    except Exception as e:
        print(f"An unexpected error occurred during memory allocation: {e}", file=sys.stderr)
        raise  # Re-raise the exception to force the caller to handle it


def free_person(person_ptr):
    """
    Frees the memory allocated for a Person object.  Sets the pointer to None to prevent use-after-free.

    Args:
        person_ptr: A pointer to the Person object to be freed.
    """
    if person_ptr:
        # Check if the pointer has already been freed.
        if person_ptr.contents is None:  # Or some other check to indicate it's already freed
            print("Warning: Attempting to free an already freed pointer.", file=sys.stderr)
            return

        # No explicit free needed with ctypes create_string_buffer.
        # The memory is managed by the buffer.
        # However, if you used a different allocation method (e.g., malloc),
        # you would need to use ctypes.free(person_ptr) here.
        # IMPORTANT: If using malloc/free, set person_ptr to None after freeing!
        person_ptr.contents = None  # Invalidate the contents to help detect double frees
        person_ptr = None # Mitigation for use-after-free.  Not strictly necessary here, but good practice.
    else:
        print("Warning: Attempting to free a null pointer.", file=sys.stderr)


if __name__ == '__main__':
    # Example usage:
    try:
        person_ptr = allocate_person()

        if person_ptr:
            print(f"Person allocated at memory address: {person_ptr}")
            print(f"Initial status: {person_ptr.contents.status}")

            # Modify the status (example)
            person_ptr.contents.status = 1

            print(f"Modified status: {person_ptr.contents.status}")

            free_person(person_ptr)
            print("Person memory freed.")

            # Example of trying to use the pointer after freeing (should be avoided!)
            # try:
            #     print(f"Status after free: {person_ptr.contents.status}") # This will likely cause an error
            # except Exception as e:
            #     print(f"Error accessing freed memory: {e}", file=sys.stderr)

        else:
            print("Failed to allocate person.", file=sys.stderr)
    except MemoryError:
        print("Memory allocation failed in main.", file=sys.stderr)
    except OSError:
        print("OS error during allocation in main.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)

