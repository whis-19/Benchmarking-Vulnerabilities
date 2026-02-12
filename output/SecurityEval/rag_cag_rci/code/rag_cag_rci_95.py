# Consider adding rate limiting to prevent abuse.
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address

# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )

# @app.route("/upload")
# @limiter.limit("10 per minute")  # Example: Limit uploads to 10 per minute
# def upload():
#     # ... your upload logic ...

