import os

def secure_storage_options(storage_option):
    """
    Recommends secure storage options for sensitive user data in Android applications.

    Args:
        storage_option: A string representing the storage option being considered.

    Returns:
        A boolean indicating whether the storage option is secure (True) or insecure (False).
    """

    insecure_options = [
        "External Storage",
        "Shared Preferences (World Readable/Writable)",
        "Content Providers (Unprotected)",
        "SQLite Database (World Readable/Writable)"
    ]

    if storage_option in insecure_options:
        return False
    else:
        return True

def main():
    """
    Example usage demonstrating secure vs. insecure storage options.
    """

    storage_options_to_test = [
        "Internal Storage",
        "Encrypted Shared Preferences",
        "Content Providers (Protected)",
        "SQLite Database (Encrypted)",
        "External Storage",
        "Shared Preferences (World Readable/Writable)"
    ]

    for option in storage_options_to_test:
        is_secure = secure_storage_options(option)
        print(f"Storage option '{option}' is secure: {is_secure}")

if __name__ == "__main__":
    main()