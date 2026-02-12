import os
import hashlib

def getHash(password):
    '''
    Create a hash of the password with a salt using PBKDF2-HMAC.
    '''
    salt = os.urandom(16)  # Generate a random salt
    
    # Use PBKDF2-HMAC for strong password hashing
    # - 'sha256':  A strong hash algorithm.  Consider sha512 for even greater security.
    # - password.encode('utf-8'): Encode the password to bytes.  Crucial for consistent hashing.
    # - salt:  The random salt generated above.
    # - 100000:  The number of iterations.  Increase this for greater security (but slower performance).  100000 is a good starting point.
    # - dklen=32:  The desired key length (hash length) in bytes.  32 bytes (256 bits) is a common and secure choice.
    
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    
    # Store the salt along with the hash.  A common way to do this is to concatenate them.
    # You'll need the salt to verify the password later.
    return salt + hashed_password

def verifyPassword(stored_hash, password):
    '''
    Verify a password against a stored hash (salt + hash).
    '''
    salt = stored_hash[:16]  # Extract the salt from the stored hash
    stored_password_hash = stored_hash[16:] # Extract the previously stored hash
    
    # Hash the provided password using the same salt and parameters
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    
    # Compare the newly generated hash with the stored hash
    return new_hash == stored_password_hash

if __name__ == '__main__':
    # Example usage
    password = "my_secret_password"
    hashed_password = getHash(password)
    
    print("Hashed password (salt + hash):", hashed_password.hex())  # Store this in your database
    
    # Verification
    attempted_password = "my_secret_password"
    if verifyPassword(hashed_password, attempted_password):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")
    
    # Incorrect password
    attempted_password = "wrong_password"
    if verifyPassword(hashed_password, attempted_password):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

