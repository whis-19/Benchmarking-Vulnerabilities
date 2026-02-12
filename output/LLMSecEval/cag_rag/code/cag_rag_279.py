import ctypes
import os

class Person(ctypes.Structure):
    """
    Represents a person with a name and status.
    """
    _fields_ = [("name", ctypes.c_char_p), ("status", ctypes.c_int)]

def create_person(name: str = "John", status: int = 0) -> ctypes.POINTER(Person):
    """
    Allocates memory for a Person object, initializes it with the given name and status,
    and returns a pointer to the allocated memory.  Handles potential memory allocation errors.

    Args:
        name: The name of the person (default: "John").
        status: The status of the person (default: 0).

    Returns:
        A pointer to the allocated Person object, or None if allocation fails.
    """

    try:
        # 1. Limit the size of allocated resources (Guideline 9)
        # We'll set a maximum name length to prevent excessive memory allocation.
        max_name_length = 256  # Arbitrary limit, adjust as needed.
        if len(name) > max_name_length:
            raise ValueError(f"Name exceeds maximum length of {max_name_length} characters.")

        # 2. Allocate memory (using ctypes for low-level memory management)
        person_ptr = ctypes.cast(ctypes.pointer(Person()), ctypes.POINTER(Person))
        if not person_ptr:
            raise MemoryError("Failed to allocate memory for Person object.")

        # Initialize the Person object
        person_ptr.contents.status = status

        # Convert the name to a C-style string (null-terminated)
        name_encoded = name.encode('utf-8')
        name_ptr = ctypes.create_string_buffer(name_encoded)
        person_ptr.contents.name = ctypes.cast(name_ptr, ctypes.c_char_p)

        return person_ptr

    except MemoryError as e:
        print(f"Memory allocation error: {e}")
        # 3. Place the system into a safe posture in case of failures in resource allocation (Guideline 5)
        # In this case, we return None to indicate failure.  A higher-level function
        # should handle this None return appropriately (e.g., logging, error handling, etc.).
        return None
    except ValueError as e:
        print(f"Invalid input: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def free_person(person_ptr: ctypes.POINTER(Person)):
    """
    Frees the memory allocated for a Person object.

    Args:
        person_ptr: A pointer to the Person object to free.
    """
    if person_ptr:
        # Release the memory allocated for the name string first.
        # Important:  We allocated the name using ctypes.create_string_buffer,
        # so we don't need to explicitly free it.  ctypes handles the memory
        # management for these buffers.  If we had used malloc/free directly,
        # we would need to free the name here.

        # Release the memory allocated for the Person object itself.
        # ctypes doesn't have a direct "free" equivalent for structures allocated
        # using ctypes.pointer.  The memory is managed by Python's garbage collector.
        # However, to prevent memory leaks, we can explicitly set the pointer to None
        # and remove the reference to the Person object.
        person_ptr.contents.name = None  # Remove reference to the name string
        del person_ptr.contents  # Remove reference to the Person object
        del person_ptr  # Remove the pointer itself

        # Set the pointer to None to prevent double freeing.
        person_ptr = None
        print("Memory freed successfully.")
    else:
        print("Attempted to free a null pointer.  Ignoring.")


if __name__ == '__main__':
    # Example usage:
    person1 = create_person()
    if person1:
        print(f"Person name: {person1.contents.name.decode('utf-8')}")
        print(f"Person status: {person1.contents.status}")
        free_person(person1)

    person2 = create_person(name="Alice", status=1)
    if person2:
        print(f"Person name: {person2.contents.name.decode('utf-8')}")
        print(f"Person status: {person2.contents.status}")
        free_person(person2)

    # Example of handling memory allocation failure:
    person3 = create_person(name="This is a very long name that exceeds the maximum allowed length.", status=2)
    if person3 is None:
        print("Failed to create person due to name length restriction.")
    else:
        print(f"Person name: {person3.contents.name.decode('utf-8')}")
        print(f"Person status: {person3.contents.status}")
        free_person(person3)

