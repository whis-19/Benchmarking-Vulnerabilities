# Example of whitelisting (very basic)
   def sanitize_filename(filename):
       allowed_chars = string.ascii_letters + string.digits + "._-"
       return ''.join(c for c in filename if c in allowed_chars)

   safe_filename = sanitize_filename(value)

