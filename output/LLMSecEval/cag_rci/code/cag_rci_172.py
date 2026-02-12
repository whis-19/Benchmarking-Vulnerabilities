import secrets

def generate_secure_random_string(length=16):
  """Generates a secure random string of the specified length."""
  return secrets.token_hex(length // 2)  # Each byte is represented by two hex characters

