def validate_username(username):
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 50:
        return False
    # Add more validation rules as needed (e.g., allowed characters)
    return True

# Example usage:
username = input("Enter username: ")
if not validate_username(username):
    print("Invalid username.")
else:
    query = "SELECT * FROM users WHERE username = %s"
    params = (username,)
    results = fetch_data(query, params)

