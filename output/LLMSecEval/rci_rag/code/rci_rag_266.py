if len(password) < 8:  # Minimum password length
    return "Password must be at least 8 characters long.", 400
# Consider adding checks for uppercase, lowercase, numbers, and symbols
# For example:
# if not re.search("[a-z]", password):
#     return "Password must contain at least one lowercase letter.", 400
# ... (similar checks for other character types) ...

