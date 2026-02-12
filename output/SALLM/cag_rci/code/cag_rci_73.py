from flask_limiter.errors import RateLimitExceeded

    @app.errorhandler(RateLimitExceeded)
    def ratelimit_handler(e):
        return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

