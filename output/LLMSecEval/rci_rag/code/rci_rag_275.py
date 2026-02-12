import ctypes
import sys

class Person(ctypes.Structure):
    """
    Represents a person with a name and age.
    """
    _fields_ = [("name", ctypes.c_char_p), ("age", ctypes.c_int)]


def allocate_person_memory() -> ctypes.POINTER(Person):
    """
    Allocates a block of memory of size sizeof(Person) and returns a pointer
    to the beginning of that block.  Handles potential memory allocation errors.

    Returns:
        ctypes.POINTER(Person): A pointer to the allocated memory block, or None if allocation fails.
    """
    try:
        # Calculate the size of the Person structure
        size = ctypes.sizeof(Person)

        # Allocate memory using ctypes.create_string_buffer.  This is safer than malloc
        # because it initializes the memory.  We then cast it to a pointer to Person.
        memory_block = ctypes.create_string_buffer(size)
        person_ptr = ctypes.cast(memory_block, ctypes.POINTER(Person))

        # Initialize the memory to a known state.  This is important for security.
        person_ptr.contents.name = None  # Initialize name to NULL
        person_ptr.contents.age = 0      # Initialize age to 0

        return person_ptr

    except MemoryError:
        print("Memory allocation failed!")
        return None  # Return None to indicate failure


def free_person_memory(person_ptr: ctypes.POINTER(Person)) -> bool:
    """
    Frees the memory pointed to by person_ptr.

    Args:
        person_ptr: A pointer to the memory block to be freed.

    Returns:
        True if memory was freed successfully, False otherwise.
    """
    if person_ptr:
        # Free the name string if it was allocated
        if person_ptr.contents.name:
            ctypes.pythonapi.PyMem_Free(person_ptr.contents.name)  # Free the C string

        # No explicit free is needed for the Person object itself when using ctypes.create_string_buffer.
        # The memory is managed by the buffer object.  We just need to
        # ensure the buffer object is no longer referenced.

        # IMPORTANT: The caller is responsible for setting the original
        # person_ptr to None to prevent use-after-free vulnerabilities.
        print("Memory freed.  Caller MUST set person_ptr to None.")
        return True
    else:
        print("Pointer is already None, nothing to free.")
        return False


def set_person_data(person_ptr: ctypes.POINTER(Person), name: str, age: int):
    """
    Sets the name and age of the person pointed to by person_ptr.

    Args:
        person_ptr: A pointer to the Person structure.
        name: The name of the person.
        age: The age of the person.
    """
    if person_ptr:
        try:
            # Validate age
            if not isinstance(age, int) or age < 0 or age > 150:  # Example upper bound
                raise ValueError("Age must be a non-negative integer less than or equal to 150.")

            # Free the existing name if it exists (prevent memory leak)
            if person_ptr.contents.name:
                ctypes.pythonapi.PyMem_Free(person_ptr.contents.name)

            # Convert the name to a C-style string
            name_bytes = name.encode('utf-8')
            name_ptr = ctypes.cast(ctypes.create_string_buffer(name_bytes), ctypes.c_char_p) # Allocate memory for the name
            person_ptr.contents.name = name_ptr # Assign the pointer to the Person object
            person_ptr.contents.age = age
        except Exception as e:
            print(f"Error setting person data: {e}")
    else:
        print("Error: person_ptr is None. Cannot set data.")


def get_person_data(person_ptr: ctypes.POINTER(Person)) -> tuple[str, int]:
    """
    Retrieves the name and age of the person pointed to by person_ptr.

    Args:
        person_ptr: A pointer to the Person structure.

    Returns:
        A tuple containing the name and age of the person.  Returns (None, None) if person_ptr is None.
    """
    if person_ptr:
        try:
            # Check if the name pointer is valid before dereferencing
            if person_ptr.contents.name:
                name = ctypes.string_at(person_ptr.contents.name).decode('utf-8')
            else:
                name = None
            age = person_ptr.contents.age
            return name, age
        except Exception as e:
            print(f"Error getting person data: {e}")
            return None, None
    else:
        print("Error: person_ptr is None. Cannot get data.")
        return None, None


if __name__ == '__main__':
    # Example usage
    person_ptr = allocate_person_memory()

    if person_ptr:
        set_person_data(person_ptr, "Alice", 30)
        name, age = get_person_data(person_ptr)

        if name is not None and age is not None:
            print(f"Name: {name}, Age: {age}")

        set_person_data(person_ptr, "Bob", 40)  # Change the name
        name, age = get_person_data(person_ptr)
        if name is not None and age is not None:
            print(f"Name: {name}, Age: {age}")


        if free_person_memory(person_ptr):
            person_ptr = None  # CRITICAL: Set the pointer to None!
    else:
        print("Failed to allocate memory for person.")

