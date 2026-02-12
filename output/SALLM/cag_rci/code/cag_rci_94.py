# XPath Injection (Regex Refinement)
def sanitize_xpath(xpath):
    """
    Sanitizes the XPath expression to prevent XPath injection attacks.
    """
    pattern = r"^/([a-zA-Z0-9_]+)\[@([a-zA-Z0-9_]+)='([a-zA-Z0-9_]+(?<![`\"]))'\]$" # Added negative lookahead
    match = re.match(pattern, xpath)
    # ... (rest of the function remains the same)

# Rate Limiting (Dynamic Limits)
from flask_login import current_user

def get_user_id():
    if current_user.is_authenticated:
        return current_user.id
    return get_remote_address()

limiter = Limiter(
    get_user_id,  # Use user ID or IP address as the key
    app=app,
    default_limits=["200 per day", "50 per hour"],
    key_func=get_user_id
)

@app.route('/xpath_query', methods=['POST'])
@limiter.limit("100/minute;2000/day", key_func=lambda: current_user.id if current_user.is_authenticated and current_user.is_premium else get_remote_address())
@csrf.protect
def xpath_query():
    # ...

# Error Handling (Custom Error Pages)
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

