from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from flask_talisman import Talisman
import time
import random

app = Flask(__name__)

#  Important:  Configure ProxyFix based on your proxy setup.
#  WARNING: Incorrectly configuring ProxyFix can completely negate your rate limiting
#  and expose your application to brute-force attacks.  Carefully review the Flask
#  documentation and your proxy's configuration before using it.  The `x_for=1`
#  argument tells Flask to trust the *last* IP address in the X-Forwarded-For header
#  (assuming your proxy adds its own IP to the end).  Adjust this value if you have
#  multiple proxies.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Apply security headers
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '*'
})


limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# In-memory account lockout (replace with a persistent store in production)
account_lockouts = {}  # {username: lockout_timestamp}

@app.route("/login")
@limiter.limit("10 per minute")  # Limit login attempts
def login():
    try:
        # ... your login logic ...
        # Example (replace with your actual logic):
        username = request.form.get('username')
        password = request.form.get('password')

        # Account Lockout Check
        if username in account_lockouts and account_lockouts[username] > time.time():
            remaining_lockout = account_lockouts[username] - time.time()
            logger.warning(f"Account {username} locked out. Remaining time: {remaining_lockout:.2f} seconds.")
            return f"Account locked out. Please try again in {remaining_lockout:.2f} seconds.", 429

        if username == "test" and password == "password":  # Insecure example!
            logger.info(f"Successful login for user: {username} from IP: {get_remote_address()}")
            # Reset lockout on successful login
            if username in account_lockouts:
                del account_lockouts[username]
            return "Login successful"
        else:
            logger.warning(f"Failed login attempt from IP: {get_remote_address()} for user: {username}")

            # Account Lockout Implementation (Exponential Backoff)
            lockout_duration = 60  # Initial lockout duration (seconds)
            if username in account_lockouts:
                lockout_duration = min(3600, (account_lockouts.get(username + "_attempts", 0) + 1) * lockout_duration) # Max 1 hour lockout
                account_lockouts[username + "_attempts"] = account_lockouts.get(username + "_attempts", 0) + 1
            else:
                account_lockouts[username + "_attempts"] = 1

            account_lockouts[username] = time.time() + lockout_duration
            logger.info(f"Account {username} locked out for {lockout_duration} seconds.")

            # Account Enumeration Prevention:  Consistent error message and timing
            time.sleep(random.uniform(0.1, 0.3))  # Add a small, random delay
            return "Invalid username or password", 401  # Generic error message

    except Exception as e:
        logger.error(f"Error during login: {e}")
        return "Internal Server Error", 500

@app.errorhandler(429)
def ratelimit_handler(e):
    rate_limit = request.rate_limit  # Access the rate limit that was exceeded
    logger.warning(f"Rate limit exceeded for IP: {get_remote_address()}. Limit: {rate_limit}")
    return "Rate limit exceeded", 429


if __name__ == '__main__':
    app.run(debug=True)

