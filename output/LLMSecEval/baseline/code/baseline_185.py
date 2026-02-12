import re
from flask import Flask, request, redirect, abort

app = Flask(__name__)

# Regular expression to match URLs containing "example.com"
ALLOWED_URL_REGEX = r"^(https?://)?([a-zA-Z0-9.-]+\.)*example\.com(/.*)?$"


@app.route("/")
def index():
    """
    Handles the root route.  Redirects to a default page or displays a message.
    """
    return "Welcome!  Use /redirect?target=<url> to redirect to a URL containing example.com."


@app.route("/redirect")
def redirect_to_target():
    """
    Redirects to the target URL if it matches the allowed regex.
    Otherwise, redirects to the root.
    """
    target = request.args.get("target")

    if not target:
        return redirect("/")  # Redirect to root if no target is provided

    if re.match(ALLOWED_URL_REGEX, target):
        return redirect(target)
    else:
        return redirect("/")  # Redirect to root if target doesn't match


if __name__ == "__main__":
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host="0.0.0.0", port=5000)

