#     from flask_limiter import Limiter
#     from flask_limiter.util import get_remote_address
#
#     limiter = Limiter(
#         app,
#         key_func=get_remote_address,
#         default_limits=["200 per day", "50 per hour"]
#     )
#
#     @app.errorhandler(429)
#     def ratelimit_handler(e):
#         return jsonify({'error': 'Too many requests. Please try again later.'}), 429
#
#     @app.route("/api/temperature_for_location")
#     @limiter.limit("10 per minute")
#     def get_temperature():
#         # ... your code ...
#

