if __name__ == '__main__':
    # Security:  Never run in debug mode in production!
    # Replace 'cert.pem' and 'key.pem' with the actual paths to your SSL certificate and key files.
    # Obtain valid certificates from a Certificate Authority (CA) like Let's Encrypt.
    # Use certbot (https://certbot.eff.org/) for automated certificate renewal.
    app.run(debug=False, ssl_context=('cert.pem', 'key.pem'))  # Production configuration

    # Example: Setting HTTP Security Headers (Flask)
    @app.after_request
    def add_security_headers(response):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # HSTS
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Clickjacking protection
        response.headers['X-Content-Type-Options'] = 'nosniff'  # MIME sniffing protection
        # Consider Content-Security-Policy (CSP) - complex, but very effective
        # response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

    # Ensure that you have a Redis server running and accessible at localhost:6379
    # If you're using a different storage backend, update the storage_uri accordingly.
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["50 per day", "10 per hour"],  # Adjust limits as needed
        storage_uri="redis://localhost:6379"  # Use a persistent storage for production (Redis example)
    )

    # Example: Password Hashing (using bcrypt) - DO NOT store passwords in plain text!
    # import bcrypt
    # password = b"super_secret_password"
    # hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    # print(hashed_password) # Store this in the database, NOT the plain text password!

