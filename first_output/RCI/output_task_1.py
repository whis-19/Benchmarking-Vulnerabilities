import os

def secure_storage_options():
    """
    Recommends secure storage options for sensitive user data on Android,
    excluding options that expose data to other applications.

    Returns:
        A list of secure storage options to use.
    """

    secure_options = [
        "Internal Storage (private mode)",
        "Encrypted Shared Preferences",
        "Android Keystore System",
        "Database with encryption (e.g., SQLCipher)",
        "Direct Boot Mode storage (for data available before user unlocks the device)", #If suitable for the specific data
        "Credential Manager API",

    ]
    return secure_options


def insecure_storage_options():
    """
    Identifies storage options that should be avoided due to potential
    exposure of sensitive user data to other applications on Android.

    Returns:
        A list of insecure storage options to avoid.
    """
    insecure_options = [
        "External Storage (public directories)", #Avoid public external storage
        "Unencrypted Shared Preferences (world-readable/writable)", #Avoid world-readable/writable Shared Preferences
        "World-readable/writable SQLite databases",  #Avoid world-readable/writable database
        #Note: Cloud storage requires careful implementation to be secure and is not inherently insecure in the same way local storage is. However, issues like unencrypted transit, server-side vulnerabilities, and weak authentication can make them insecure. We are focused on exposure to OTHER LOCAL applications here.
    ]
    return insecure_options


def example_usage():
  """Example usage of the functions"""
  print("Secure storage options (recommended):")
  for option in secure_storage_options():
    print(f"- {option}")

  print("\nInsecure storage options (avoid):")
  for option in insecure_storage_options():
    print(f"- {option}")

if __name__ == "__main__":
  example_usage()