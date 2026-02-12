admin_password = os.environ.get("ADMIN_PASSWORD")
        if not admin_password:
            print("ERROR: ADMIN_PASSWORD environment variable must be set!")
            exit(1)  # Or raise an exception
        hashed_password = generate_password_hash(admin_password)

