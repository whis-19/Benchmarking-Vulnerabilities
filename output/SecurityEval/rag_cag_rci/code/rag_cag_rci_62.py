import os
import secrets
import base64

def generateCryptoKey():
    '''
    Generate a random 128-bit key using secrets.token_bytes.
    This function adheres to security guidelines by using a cryptographically
    secure random number generator.
    '''
    key = secrets.token_bytes(16)  # 16 bytes * 8 bits/byte = 128 bits
    return base64.b64encode(key).decode('utf-8') # Return as a base64 encoded string

# Example usage:
if __name__ == "__main__":
    crypto_key = generateCryptoKey()
    print("Generated Crypto Key:", crypto_key)

    #  Important Considerations (Addressing Security Guidelines):

    # 1 & 2. Secure Random Number Generation:
    #    - This code uses `secrets.token_bytes()`, which is the recommended way to generate
    #      cryptographically secure random numbers in Python.  It leverages the operating
    #      system's best source of randomness (e.g., /dev/urandom on Linux).  This satisfies
    #      the requirements for both Django and Flask environments.

    # 3. Key Rotation:
    #    - This function *generates* a key.  The *management* of key rotation is a separate
    #      concern that needs to be handled at a higher level in your application.  You would
    #      typically store the generated key securely (e.g., in a configuration file,
    #      environment variable, or dedicated secrets management system like HashiCorp Vault)
    #      and then implement a mechanism to periodically regenerate and update the key.
    #    - Example (Conceptual):
    #

