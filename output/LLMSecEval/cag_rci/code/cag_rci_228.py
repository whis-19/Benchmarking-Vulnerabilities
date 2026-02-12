# ... (rest of the code)

@app.route("/")
def index():
    """Renders the index page."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return render_template("index.html", products=products, nonce=g.csp_nonce, csrf_token=session['_csrf_token'])

# Example HTML template snippet (index.html):
# <form action="/calculate" method="POST">
#   <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
#   ... (rest of the form)
# </form>

# Example of session regeneration (if you have a login route):
# @app.route("/login", methods=["POST"])
# def login():
#     # ... (authentication logic)
#     if authentication_successful:
#         session.regenerate()  # Prevent session fixation
#         return redirect(url_for("index"))
#     else:
#         return render_template("login.html", error="Invalid credentials")

