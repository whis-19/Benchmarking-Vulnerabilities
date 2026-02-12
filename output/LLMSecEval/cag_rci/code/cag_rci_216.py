from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address

        limiter = Limiter(
            app,
            key_func=get_remote_address,
            default_limits=["200 per day, 50 per hour"]  # Example limits
        )

        @app.route("/login", methods=["POST"])
        @limiter.limit("5 per minute")  # More aggressive limit for login
        def login():
            # ... your login logic ...
            return "Login successful"

