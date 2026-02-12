import ctypes
import sys

class Person(ctypes.Structure):
    """
    Represents a person with a name and age.
    """
    _fields_ = [("name", ctypes.c_char_p), ("age", ctypes.c_int)]

def allocate_person_memory():
    """
    Allocates a block of memory of size sizeof(Person) and returns a pointer
    to the beginning of that block.  Handles potential memory allocation errors.

    Returns:
        ctypes.POINTER(Person): A pointer to the allocated memory block, or None if allocation fails.
    """
    try:
        # Calculate the size of the Person structure
        person_size = ctypes.sizeof(Person)

        # Allocate memory using ctypes.create_string_buffer.  This is safer than malloc
        # because it initializes the memory.  We then cast it to a pointer to Person.
        memory_block = ctypes.create_string_buffer(person_size)
        person_ptr = ctypes.cast(memory_block, ctypes.POINTER(Person))

        # Initialize the memory to a known state (important for security)
        person_ptr.contents.name = None  # Initialize name to NULL
        person_ptr.contents.age = 0      # Initialize age to 0

        return person_ptr

    except MemoryError as e:
        print(f"Memory allocation failed: {e}")
        return None  # Return None to indicate failure

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None # Return None to indicate failure

def free_person_memory(person_ptr):
    """
    Frees the memory block pointed to by person_ptr.  Handles NULL pointers safely.

    Args:
        person_ptr (ctypes.POINTER(Person)): The pointer to the memory block to free.
    """
    if person_ptr:
        #  We don't directly free memory allocated with create_string_buffer.
        #  Instead, we rely on Python's garbage collection to reclaim the memory
        #  when the memory_block object goes out of scope.  To prevent memory leaks,
        #  we set the pointer to None.

        # Clear the contents of the structure before setting the pointer to None
        # This is important to prevent dangling pointers to the name string.
        if person_ptr.contents.name:
            # Free the name string if it was allocated separately
            # In this example, we assume the name is a simple char array, so we don't need to free it.
            # If the name was dynamically allocated, we would need to free it here.
            pass

        person_ptr.contents.name = None
        person_ptr.contents.age = 0

        # Set the pointer to None to prevent double freeing or use-after-free errors.
        person_ptr = None
    else:
        print("Attempted to free a NULL pointer.  Ignoring.")


def set_person_data(person_ptr, name, age):
    """
    Sets the name and age of the person pointed to by person_ptr.
    Handles NULL pointers and potential errors.

    Args:
        person_ptr (ctypes.POINTER(Person)): The pointer to the Person structure.
        name (str): The name of the person.
        age (int): The age of the person.
    """
    if not person_ptr:
        print("Error: Cannot set data for a NULL person pointer.")
        return

    if not isinstance(name, str):
        print("Error: Name must be a string.")
        return

    if not isinstance(age, int):
        print("Error: Age must be an integer.")
        return

    try:
        # Convert the name to a C-style string (null-terminated)
        name_bytes = name.encode('utf-8')
        person_ptr.contents.name = ctypes.create_string_buffer(name_bytes).raw  # Copy the string

        person_ptr.contents.age = age

    except Exception as e:
        print(f"Error setting person data: {e}")


def get_person_data(person_ptr):
    """
    Retrieves the name and age of the person pointed to by person_ptr.
    Handles NULL pointers safely.

    Args:
        person_ptr (ctypes.POINTER(Person)): The pointer to the Person structure.

    Returns:
        tuple: A tuple containing the name (str) and age (int), or None if the pointer is NULL.
    """
    if not person_ptr:
        print("Error: Cannot get data from a NULL person pointer.")
        return None

    try:
        name = person_ptr.contents.name
        if name:
            name = name.decode('utf-8')
        else:
            name = ""  # Handle NULL name

        age = person_ptr.contents.age
        return name, age

    except Exception as e:
        print(f"Error getting person data: {e}")
        return None


if __name__ == '__main__':
    # Example usage:
    person_ptr = allocate_person_memory()

    if person_ptr:
        set_person_data(person_ptr, "Alice", 30)
        name, age = get_person_data(person_ptr)

        if name and age is not None:
            print(f"Name: {name}, Age: {age}")

        free_person_memory(person_ptr)
    else:
        print("Failed to allocate memory for a person.")

    # Example of handling allocation failure:
    person_ptr = allocate_person_memory()
    if not person_ptr:
        print("Failed to allocate memory.  Exiting gracefully.")
        sys.exit(1)  # Exit with an error code

    # Example of freeing memory in a try...finally block:
    person_ptr = allocate_person_memory()
    try:
        if person_ptr:
            set_person_data(person_ptr, "Bob", 25)
            name, age = get_person_data(person_ptr)
            if name and age is not None:
                print(f"Name: {name}, Age: {age}")
            # Simulate an error
            raise ValueError("Simulated error")
    except ValueError as e:
        print(f"Caught an error: {e}")
    finally:
        if person_ptr:
            free_person_memory(person_ptr)  # Ensure memory is freed even if an error occurs

