import ctypes

MAX_NAME_LENGTH = 64  # Define a maximum name length

class Person(ctypes.Structure):
    """
    Represents a person with a name and age.
    The name is stored in a fixed-size character array to prevent buffer overflows.
    """
    _fields_ = [("name", ctypes.c_char * MAX_NAME_LENGTH),  # Fixed-size char array
                ("age", ctypes.c_int)]


def allocate_person_memory():
    """
    Allocates a block of memory of size sizeof(Person) and returns a pointer
    to the beginning of that block.  Uses ctypes for memory management.

    Returns:
        ctypes.POINTER(Person): A pointer to the allocated memory block,
                                 cast as a pointer to a Person structure.
                                 Returns None if allocation fails.
    """
    try:
        # Calculate the size of the Person structure
        person_size = ctypes.sizeof(Person)

        # Uses ctypes.create_string_buffer() for allocation: This is the *safest* way to allocate memory in this scenario.
        # By allocating a fixed-size buffer with `ctypes.create_string_buffer`, we ensure that any attempt to write more
        # data than the buffer can hold will result in an error, preventing a buffer overflow.  However, it's crucial to
        # use a fixed-size character array within the Person structure itself, rather than relying solely on
        # create_string_buffer to protect the *Person* structure.  The original code had a vulnerability because the
        # `name` field was a `c_char_p` (pointer to char), which could point to memory outside the allocated buffer.
        memory_block = ctypes.create_string_buffer(person_size)

        # Cast the memory block to a pointer to a Person structure.  This allows
        # us to treat the allocated memory as a Person object.
        person_ptr = ctypes.cast(memory_block, ctypes.POINTER(Person))

        return person_ptr

    except MemoryError:
        print("Memory allocation failed!")
        return None  # Handle memory allocation failure gracefully


def free_person_memory(person_ptr):
    """
    Frees the memory block pointed to by person_ptr.  This is crucial to
    prevent memory leaks.  Since we used ctypes.create_string_buffer,
    the memory is automatically managed by Python's garbage collector
    when the `memory_block` variable goes out of scope.  Therefore,
    explicitly freeing the memory is not necessary and can lead to errors.
    This function is included for completeness and to demonstrate the
    concept of freeing memory, but it's effectively a no-op in this case.

    Args:
        person_ptr (ctypes.POINTER(Person)): The pointer to the memory block
                                             to be freed.
    """
    # No explicit deallocation needed when using ctypes.create_string_buffer.
    # The memory is managed by Python's garbage collector.
    # This function is included for conceptual completeness.
    pass


if __name__ == '__main__':
    # Example usage:
    person_ptr = allocate_person_memory()

    if person_ptr:
        name_to_assign = b"Alice"  # Must be a byte string

        # Ensure the name is not longer than the maximum allowed length
        if len(name_to_assign) < MAX_NAME_LENGTH:
            person_ptr.contents.name = name_to_assign
            person_ptr.contents.age = 30

            # Access the data
            print(f"Name: {person_ptr.contents.name.decode('utf-8')}")  # Decode byte string to regular string, specifying UTF-8 encoding
            print(f"Age: {person_ptr.contents.age}")
        else:
            print("Name is too long!")


        # Free the memory (not strictly necessary, but good practice to demonstrate)
        free_person_memory(person_ptr)

        # After freeing, the pointer is invalid.  Accessing it will likely cause a crash.
        # The following line is commented out to prevent a crash.
        # print(f"Name after free: {person_ptr.contents.name.decode()}") # DO NOT DO THIS!
    else:
        print("Failed to allocate memory for a person.")

