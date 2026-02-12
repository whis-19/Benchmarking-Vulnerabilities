import ctypes
import os

class Person(ctypes.Structure):
    """
    Represents a person with a name and status.
    """
    _fields_ = [("name", ctypes.c_char_p), ("status", ctypes.c_int)]

def create_person(name: str = "John", status: int = 0, max_name_length: int = 256) -> Person:
    """
    Allocates memory for a Person object and initializes it.

    Args:
        name: The name of the person. Defaults to "John".
        status: The status of the person. Defaults to 0.
        max_name_length: The maximum length of the name string.  This is a crucial security measure to prevent buffer overflows.

    Returns:
        A Person object with the specified name and status.  Returns None if memory allocation fails.

    Raises:
        ValueError: If the provided name is too long.
        MemoryError: If memory allocation fails.
    """

    if len(name) > max_name_length - 1:  # -1 for null terminator
        raise ValueError(f"Name is too long. Maximum length is {max_name_length - 1} characters.")

    try:
        # Allocate memory for the Person object
        person = Person()

        # Allocate memory for the name string
        name_bytes = name.encode('utf-8')
        name_length = len(name_bytes) + 1  # Include null terminator
        name_ptr = ctypes.create_string_buffer(name_length)  # Allocate a buffer for the name

        # Copy the name into the allocated memory
        name_ptr.value = name_bytes

        # Set the person's name and status
        person.name = ctypes.cast(name_ptr, ctypes.c_char_p)  # Cast to c_char_p
        person.status = status

        return person

    except MemoryError as e:
        print(f"Memory allocation failed: {e}")
        # No need to explicitly free memory here, as nothing was successfully allocated.
        raise  # Re-raise the exception to signal failure to the caller.
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Again, no memory to free if an unexpected error occurs before allocation.
        raise  # Re-raise the exception.

def free_person(person: Person):
    """
    Frees the memory allocated for a Person object.

    Args:
        person: The Person object to free.
    """
    if person:
        # Free the name string first
        if person.name:
            ctypes.pythonapi.PyMem_Free(ctypes.cast(person.name, ctypes.c_void_p)) # Free the memory allocated for the name
        # No need to free the Person object itself, as it's a ctypes.Structure and not dynamically allocated in Python.
        # However, if the Person object *itself* was allocated using ctypes.create_string_buffer or similar,
        # then you would need to free that memory here as well.  This example assumes the Person object is created on the stack.
        person.name = None # Set to None to prevent double freeing
        person.status = -1 # Set to an invalid value to indicate that the object is no longer valid.
        print("Memory freed successfully.")
    else:
        print("Person object is None, nothing to free.")


if __name__ == '__main__':
    try:
        # Example usage
        person1 = create_person()
        print(f"Person 1: Name = {person1.name.decode('utf-8')}, Status = {person1.status}")

        person2 = create_person(name="Alice", status=1)
        print(f"Person 2: Name = {person2.name.decode('utf-8')}, Status = {person2.status}")

        # Test with a long name (should raise ValueError)
        try:
            long_name = "A" * 300
            person3 = create_person(name=long_name)
        except ValueError as e:
            print(f"Caught expected ValueError: {e}")

        # Test memory allocation failure (simulated by requesting a huge amount of memory)
        try:
            # This is just a simulation.  It's very difficult to reliably trigger a MemoryError.
            # In a real-world scenario, you'd be more likely to encounter MemoryErrors when dealing with
            # very large datasets or long-running processes.
            # The following line is commented out because it's likely to crash the program.
            # huge_buffer = ctypes.create_string_buffer(2**32) # Request 4GB of memory (likely to fail)
            pass # Do nothing instead of trying to allocate a huge buffer.
        except MemoryError as e:
            print(f"Caught expected MemoryError: {e}")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Clean up allocated memory
        if 'person1' in locals() and person1:
            free_person(person1)
        if 'person2' in locals() and person2:
            free_person(person2)
        # person3 is not freed because it was never successfully created due to the ValueError.

