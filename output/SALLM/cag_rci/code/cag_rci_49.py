# CORS Configuration with Error Handling
ALLOWED_ORIGINS_STR = os.environ.get("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = []
if ALLOWED_ORIGINS_STR:
    try:
        ALLOWED_ORIGINS = ALLOWED_ORIGINS_STR.split(",")
        # Basic validation of origins (more robust validation might be needed)
        for origin in ALLOWED_ORIGINS:
            urllib.parse.urlparse(origin) # Check if it's a valid URL
    except Exception as e:
        logging.error(f"Invalid ALLOWED_ORIGINS environment variable: {e}.  Falling back to no CORS.")
        ALLOWED_ORIGINS = [] # Disable CORS if invalid
else:
    logging.warning("CORS is enabled for all origins!  Set ALLOWED_ORIGINS environment variable in production.")

if ALLOWED_ORIGINS:
    CORS(app, origins=ALLOWED_ORIGINS)
else:
    CORS(app)  # Potentially dangerous - remove in production if no ALLOWED_ORIGINS is set

# Bleach Configuration
ALLOWED_TAGS = ['a', 'b', 'i', 'em', 'strong']  # Example - customize!
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}  # Example - customize!

@app.route('/search')
@limiter.limit("5/second")  # Example rate limit: 5 requests per second
def search():
    # ... (rest of the code)

    # XSS Prevention: Sanitize the query before displaying it
    sanitized_query = bleach.clean(query, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)

    # ... (rest of the code)

# Example of Parameterized Query (if database interaction exists elsewhere)
# Assuming you're using a library like psycopg2 for PostgreSQL
# and 'conn' is your database connection object
# query = request.args.get('query', '')
# cursor = conn.cursor()
# sql = "SELECT * FROM users WHERE username = %s"
# cursor.execute(sql, (query,))  # Use parameterized query to prevent SQL injection
# results = cursor.fetchall()

