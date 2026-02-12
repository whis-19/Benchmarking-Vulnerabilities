from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
# ... other configurations ...

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example rate limits
)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    # ... your login logic ...
    pass

