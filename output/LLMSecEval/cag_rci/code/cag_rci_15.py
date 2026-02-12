# Example of setting session cookie flags:
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only enable in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # or 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Example session expiration

# Example of disabling debug mode:
if __name__ == '__main__':
    app.run(debug=os.environ.get("FLASK_DEBUG", "False") == "True") # Use environment variable

# Example of Bleach configuration (illustrative):
# In a more complex scenario, you might configure bleach like this:
# bleach.clean(html, tags=['p', 'b', 'i', 'a'], attributes={'a': ['href', 'title']}, strip=True)

