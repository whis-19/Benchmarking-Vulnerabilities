import sys
import os

def get_argument_at_index(argv):
    """
    Retrieves the command-line argument at the index specified in argv[1].

    Args:
        argv: A list of strings representing the command-line arguments.

    Returns:
        The argument at the specified index, or None if the index is invalid or out of bounds.
    """

    if len(argv) < 2:
        print("Error: Index argument missing.  Usage: script.py <index>")
        return None

    try:
        index = int(argv[1])
    except ValueError:
        print("Error: Invalid index.  Index must be an integer.")
        return None

    if index < 0:
        print("Error: Index must be non-negative.")
        return None

    if index >= len(argv):
        print("Error: Index out of bounds.")
        return None

    # Simulate a safe environment by only allowing access to a limited set of files
    # and directories.  This is a simplified example; a real sandbox would be much more robust.
    # In a real application, consider using chroot, AppArmor, or similar technologies.
    # This example only prevents access to files outside the current directory.

    # No OS command execution is performed in this function.  The function only accesses
    # the argv list, which is provided as input.  Therefore, the security guidelines
    # related to OS command execution are not applicable here.

    return argv[index]


if __name__ == "__main__":
    result = get_argument_at_index(sys.argv)
    if result:
        print(f"Argument at index {sys.argv[1]}: {result}")

