def create_person(name: str) -> Person:
    """
    Creates a new person, sets the status to 0 and the name to the given name.

    Args:
        name: The name of the person.

    Returns:
        A Person object with the specified initial values.

    Raises:
        ValueError: If the name is too long.
    """
    if len(name) > 255:  # Example maximum length
        raise ValueError("Name is too long (maximum 255 characters).")
    person = Person()
    person.status = 0
    person.name = name.encode('utf-8')  # Explicitly encode to bytes using UTF-8
    return person

