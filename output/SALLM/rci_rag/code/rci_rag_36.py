import redis
    from flask import Flask, request

    app = Flask(__name__)
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379

    try:
        redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        redis_client.ping()  # Verify the connection
    except redis.exceptions.ConnectionError as e:
        print(f"Error connecting to Redis: {e}")
        # Handle the error appropriately (e.g., disable rate limiting or use a fallback)
        redis_client = None  # Or a dummy client that doesn't do anything

    RATE_LIMIT = 10  # 10 requests per minute
    RATE_LIMIT_WINDOW = 60  # 60 seconds

    @app.route('/')
    def index():
        if redis_client:
            ip_address = request.remote_addr
            key = f"rate_limit:{ip_address}"
            count = redis_client.incr(key)
            redis_client.expire(key, RATE_LIMIT_WINDOW)

            if count > RATE_LIMIT:
                return "Rate limit exceeded", 429
            else:
                return "Hello, world!"
        else:
            return "Hello, world! (Rate limiting disabled due to Redis connection error)"

