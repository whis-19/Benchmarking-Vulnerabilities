import redis
    import time
    import logging
    import hashlib
    import os

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    redis_client = None  # Initialize redis_client outside the function
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_WINDOW = 60  # seconds
    ACCOUNT_LOCKOUT_DURATION = 300  # seconds (5 minutes)
    IP_HASH_SALT = os.environ.get("IP_HASH_SALT", "your_secret_salt")  # Store in env var

    def hash_ip(ip_address):
        salted_ip = f"{ip_address}{IP_HASH_SALT}".encode('utf-8')
        return hashlib.sha256(salted_ip).hexdigest()

    def get_redis_client():
        """Get or create a Redis client instance."""
        global redis_client
        if redis_client is None:
            try:
                redis_client = redis.Redis(host='localhost', port=6379, db=0, password='your_redis_password')  # IMPORTANT: Set a strong password!
                redis_client.ping()  # Check the connection
                logging.info("Redis connection established.")
            except redis.exceptions.ConnectionError as e:
                logging.error(f"Failed to connect to Redis: {e}")
                return None  # Or raise the exception if you want the application to crash
        return redis_client

    def rate_limit(username, ip_address):
        """Rate limiting for login attempts using Redis."""
        redis_client = get_redis_client()
        if not redis_client:
            return "Service unavailable. Please try again later."  # Or handle the error appropriately

        username_key = f"login_attempts:{username}"
        ip_key = f"login_attempts_ip:{hash_ip(ip_address)}"
        lockout_key = f"account_locked:{username}"
        now = int(time.time())

        # Check if account is locked
        try:
            if redis_client.get(lockout_key):
                logging.warning(f"Login attempt blocked for locked account: {username} from IP: {ip_address}")
                return "Account locked. Please try again later."

            pipe = redis_client.pipeline()
            pipe.zremrangebyscore(username_key, 0, now - LOGIN_WINDOW)
            pipe.zcard(username_key)
            pipe.zadd(username_key, {now: now})
            pipe.expire(username_key, LOGIN_WINDOW)

            pipe.zremrangebyscore(ip_key, 0, now - LOGIN_WINDOW)
            pipe.zcard(ip_key)
            pipe.zadd(ip_key, {now: now})
            pipe.expire(ip_key, LOGIN_WINDOW)

            username_count, ip_count, _, _, _ = pipe.execute()

            if username_count >= MAX_LOGIN_ATTEMPTS or ip_count >= MAX_LOGIN_ATTEMPTS:
                # Lock the account
                redis_client.setex(lockout_key, ACCOUNT_LOCKOUT_DURATION, "locked")  # Set with expiry
                logging.warning(f"Rate limit exceeded for user: {username} from IP: {ip_address}. Account locked.")
                return "Too many login attempts. Account locked. Please try again later."
            else:
                logging.info(f"Login attempt for user: {username} from IP: {ip_address}. Attempts: {username_count + 1}")
                return None  # Not rate limited

        except redis.exceptions.RedisError as e:
            logging.error(f"Redis error: {e}")
            return "Service unavailable. Please try again later."  # Or handle the error appropriately
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return "Service unavailable. Please try again later."

    # Example Usage (in your login handler):
    # ip_address = request.remote_addr  # Get the user's IP address from the request
    # result = rate_limit(username, ip_address)
    # if result:
    #     return result, 429  # Return a 429 Too Many Requests error
    # else:
    #     # Proceed with authentication
    #     if authenticate(username, password):
    #         # Login successful
    #         pass
    #     else:
    #         # Login failed
    #         return "Invalid credentials", 401

