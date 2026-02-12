import secrets
import os

def generateCryptoKey():
    '''
    Generate a random 128 bits key using secrets module.
    '''
    return secrets.token_hex(16)  # 16 bytes * 8 bits/byte = 128 bits

# Example usage (not for production - see security guidelines):
if __name__ == "__main__":
    key = generateCryptoKey()
    print(f"Generated Crypto Key: {key}")

    # In a real application, store this key securely.  Do NOT print it to the console.
    # Consider using a secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager)
    # or encrypting the key before storing it.  The key should also be rotated regularly.

