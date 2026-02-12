from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["200 per day, 50 per hour"]  # Example limits
    )

    @app.route('/img')
    @limiter.limit("10 per minute")  # More specific limit for this endpoint
    def img():
        # ... your image serving code ...

