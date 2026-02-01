# Secure storage options on Android:
# 1. Internal Storage: Files saved to the device's internal storage are private to the application by default.
#    Other applications cannot access these files. This is generally a good option for sensitive data.
# 2. External Storage: Files saved to the device's external storage (e.g., SD card) are world-readable by default.
#    Any application can access these files unless specific permissions are set. Avoid using external storage for sensitive data.
# 3. Shared Preferences: A mechanism for storing small amounts of key-value data.  While it can be made private, it's
#    not designed for large or highly sensitive data.  Consider using EncryptedSharedPreferences from androidx.security.crypto
#    for enhanced security.
# 4. SQLite Databases: Databases can be stored on internal storage and made private to the application. Use encryption
#    libraries like SQLCipher for sensitive data stored in databases.
# 5. Cloud Storage: Storing data in the cloud can be secure if proper security measures (e.g., encryption, authentication)
#    are implemented.

# In summary, the storage option to avoid for sensitive data is:
# - External Storage (without proper protection and access controls)

def demonstrate_insecure_storage():
    """
    This function demonstrates how storing sensitive data on external storage can be insecure.
    """
    import os

    # Simulate sensitive data
    sensitive_data = "This is very sensitive user data: password123"

    # Insecure: Save data to a publicly accessible file on external storage
    external_storage_path = "/sdcard/sensitive_data.txt" # Replace with the actual external storage path
    
    try:
        with open(external_storage_path, "w") as f:
            f.write(sensitive_data)
        print(f"Insecurely saved sensitive data to: {external_storage_path}")
    except Exception as e:
        print(f"Error writing to external storage: {e}")
        print("Ensure external storage is available and writable. In a real Android app, you'd use Context.getExternalFilesDir() etc.")
    
    print("WARNING: DO NOT ACTUALLY DO THIS IN A REAL APPLICATION.  THIS IS ONLY FOR DEMONSTRATION PURPOSES.")

def demonstrate_secure_storage():
    """
    Placeholder function to demonstrate how sensitive data could be stored securely.
    This requires Android-specific libraries like androidx.security.crypto.
    This placeholder only prints a message.
    """
    print("Secure storage using EncryptedSharedPreferences or internal storage with encryption would be the recommended approach.")
    print("This would require Android-specific code.")

if __name__ == "__main__":
    print("Demonstrating INSECURE data storage on external storage (DO NOT DO THIS IN REALITY):")
    demonstrate_insecure_storage()

    print("\nSecure storage (placeholder - needs Android-specific implementation):")
    demonstrate_secure_storage()