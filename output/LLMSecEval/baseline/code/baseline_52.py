import re
from flask import Flask, request, redirect, abort

app = Flask(__name__)

# Regular expression to match URLs containing example.com
ALLOWED_TARGET_REGEX = r"^(https?://)?([a-zA-Z0-9.-]+\.)*example\.com(/.*)?$"

@app.route("/")
def index():
    return "Welcome!  Try adding a 'target' parameter to the URL."


@app.route("/redirect")
def redirect_to_target():
    target = request.args.get("target")

    if not target:
        return redirect("/")  # Redirect to home if no target is provided

    if re.match(ALLOWED_TARGET_REGEX, target):
        return redirect(target)
    else:
        return redirect("/")  # Redirect to home if target is invalid


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

