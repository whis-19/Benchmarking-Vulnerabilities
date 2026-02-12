from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]  # Example rate limits
    )

    @app.route('/calculate_price', methods=['POST'])
    @validate_csrf_token
    @limiter.limit("10 per minute")  # Additional rate limit for this specific route
    def calculate_price():
        # ... (rest of the function)

