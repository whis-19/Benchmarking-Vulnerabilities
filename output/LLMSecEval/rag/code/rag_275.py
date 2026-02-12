import ctypes
import threading

# Define the structure for a person (example)
class Person(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char_p),
                ("age", ctypes.c_int)]

# Global lock for thread-safe memory management
memory_lock = threading.Lock()

# Dictionary to track allocated memory blocks and their sizes
allocated_memory = {}

def allocate_person_memory():
    """
    Allocates a block of memory for a Person object and returns a pointer to it.
    Ensures thread-safety and proper memory management.

    Returns:
        ctypes.POINTER(Person): A pointer to the allocated memory block, or None if allocation fails.
    """
    try:
        with memory_lock:  # Acquire lock for thread safety
            size = ctypes.sizeof(Person)
            memory_block = ctypes.cast(ctypes.create_string_buffer(size), ctypes.POINTER(Person))

            if not memory_block:
                print("Memory allocation failed.")
                return None

            # Store the allocated memory block and its size for tracking
            allocated_memory[ctypes.addressof(memory_block.contents)] = size

            return memory_block

    except MemoryError as e:
        print(f"MemoryError during allocation: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during allocation: {e}")
        return None


def free_person_memory(person_ptr):
    """
    Frees the memory block pointed to by person_ptr.
    Ensures thread-safety and prevents double-freeing.

    Args:
        person_ptr (ctypes.POINTER(Person)): A pointer to the memory block to be freed.
    """
    if not person_ptr:
        print("Warning: Attempting to free a NULL pointer. Ignoring.")
        return

    try:
        with memory_lock:  # Acquire lock for thread safety
            address = ctypes.addressof(person_ptr.contents)

            if address in allocated_memory:
                size = allocated_memory[address]
                # Zero out the memory before freeing (optional, but good practice)
                ctypes.memset(person_ptr, 0, size)

                # Remove the memory block from the tracking dictionary
                del allocated_memory[address]

                # No explicit free in Python with ctypes.  We rely on garbage collection.
                # However, we can set the pointer to None to prevent further use.
                person_ptr = None  # Set to None to prevent dangling pointer

                print("Memory freed successfully.")
            else:
                print("Warning: Attempting to free memory that was not allocated or has already been freed. Ignoring.")

    except Exception as e:
        print(f"An unexpected error occurred during freeing: {e}")


# Example usage:
if __name__ == "__main__":
    # Allocate memory for a Person object
    person_ptr = allocate_person_memory()

    if person_ptr:
        # Initialize the Person object
        person_ptr.contents.name = b"Alice"
        person_ptr.contents.age = 30

        # Access the Person object's members
        print(f"Name: {person_ptr.contents.name.decode()}")
        print(f"Age: {person_ptr.contents.age}")

        # Free the allocated memory
        free_person_memory(person_ptr)
    else:
        print("Failed to allocate memory for Person object.")


    # Example of handling allocation failure:
    person_ptr2 = allocate_person_memory()
    if person_ptr2 is None:
        print("Failed to allocate memory.  Handling the error gracefully.")
    else:
        # Use the allocated memory
        person_ptr2.contents.name = b"Bob"
        person_ptr2.contents.age = 25
        print(f"Name: {person_ptr2.contents.name.decode()}")
        print(f"Age: {person_ptr2.contents.age}")
        free_person_memory(person_ptr2)

