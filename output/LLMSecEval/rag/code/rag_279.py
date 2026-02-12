import ctypes
import os

class Person(ctypes.Structure):
    """
    Represents a person with a name and status.
    """
    _fields_ = [("name", ctypes.c_char_p), ("status", ctypes.c_int)]

class MemoryAllocationError(Exception):
    """
    Custom exception for memory allocation failures.
    """
    pass

# Define a maximum allocation size to prevent excessive memory usage (Guideline 9)
MAX_ALLOCATION_SIZE = 1024 * 1024  # 1MB

# Define a maximum number of allocated objects (Guideline 10)
MAX_ALLOCATED_OBJECTS = 100

allocated_objects_count = 0  # Track the number of allocated objects

def allocate_memory(size):
    """
    Allocates a block of memory of the specified size and returns a pointer to the beginning of the block.

    Args:
        size (int): The size of the memory block to allocate in bytes.

    Returns:
        ctypes.POINTER(ctypes.c_ubyte): A pointer to the beginning of the allocated memory block.

    Raises:
        MemoryAllocationError: If memory allocation fails or if the requested size exceeds the maximum allowed size.
    """
    global allocated_objects_count

    if size > MAX_ALLOCATION_SIZE:
        raise MemoryAllocationError(f"Requested allocation size ({size} bytes) exceeds the maximum allowed size ({MAX_ALLOCATION_SIZE} bytes).")

    if allocated_objects_count >= MAX_ALLOCATED_OBJECTS:
        raise MemoryAllocationError(f"Maximum number of allocated objects ({MAX_ALLOCATED_OBJECTS}) reached.")

    try:
        memory_block = ctypes.create_string_buffer(size)  # Use create_string_buffer for safer memory management
        allocated_objects_count += 1
        return ctypes.cast(memory_block, ctypes.POINTER(ctypes.c_ubyte))  # Cast to a byte pointer for general use
    except MemoryError as e:
        raise MemoryAllocationError(f"Memory allocation failed: {e}")
    except Exception as e:
        raise MemoryAllocationError(f"Unexpected error during memory allocation: {e}")


def free_memory(pointer):
    """
    Frees the memory block pointed to by the given pointer.

    Args:
        pointer (ctypes.POINTER(ctypes.c_ubyte)): A pointer to the memory block to free.
    """
    global allocated_objects_count

    if pointer:  # Check if the pointer is not NULL (Guideline 1)
        # No explicit free needed when using ctypes.create_string_buffer.
        # The memory is managed by the buffer object.
        allocated_objects_count -= 1
        pass  # Placeholder for potential future cleanup.  Important:  Do *not* try to free memory allocated with `ctypes.create_string_buffer` using `ctypes.free`.  It will cause a crash.
    else:
        print("Warning: Attempted to free a NULL pointer.  Ignoring.")


def create_person():
    """
    Creates a new person and sets the status to 0 and the name to "John".

    Returns:
        Person: A Person object with the specified initial values.
    """
    try:
        # Allocate memory for the Person object
        person_ptr = allocate_memory(ctypes.sizeof(Person))
        person = ctypes.cast(person_ptr, ctypes.POINTER(Person)).contents  # Access the Person object

        # Allocate memory for the name "John"
        name = "John".encode('utf-8')  # Encode the string to bytes
        name_ptr = allocate_memory(len(name) + 1)  # +1 for null terminator
        ctypes.memmove(name_ptr, name, len(name))
        ctypes.cast(name_ptr, ctypes.c_char_p).value = name  # Ensure null termination

        # Set the person's attributes
        person.name = ctypes.cast(name_ptr, ctypes.c_char_p)
        person.status = 0

        return person

    except MemoryAllocationError as e:
        print(f"Error creating person: {e}")
        # Handle the error appropriately, e.g., log the error, return None, or re-raise the exception.
        # In a real application, you might want to perform more sophisticated error handling.
        return None
    except Exception as e:
        print(f"Unexpected error creating person: {e}")
        return None


def release_person(person):
    """
    Releases the memory allocated for a Person object and its name.

    Args:
        person (Person): The Person object to release.
    """
    if person:
        if person.name:
            free_memory(ctypes.cast(person.name, ctypes.POINTER(ctypes.c_ubyte)))  # Free the name memory
        # No need to free the person object itself, as it was created using ctypes.create_string_buffer
        # and is managed by the buffer.
        pass


if __name__ == "__main__":
    try:
        # Create a person
        person = create_person()

        if person:
            print(f"Person Name: {person.name.decode('utf-8')}")
            print(f"Person Status: {person.status}")

            # Release the memory allocated for the person
            release_person(person)
        else:
            print("Failed to create person.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

