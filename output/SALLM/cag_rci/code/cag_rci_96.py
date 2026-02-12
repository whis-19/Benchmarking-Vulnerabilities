@app.route('/redirect', methods=['GET'])
@login_required
def redirect_url():
    """
    Redirects to a URL after validating it against an allowlist.
    **Important:**  Avoid direct redirects to user-supplied URLs.
    This example is for demonstration purposes only and should be replaced
    with a safer implementation in a real application.
    """
    # **SAFER APPROACH:**  Use a whitelist of internal redirect targets.
    # For example:
    redirect_targets = {
        "profile": "profile",  # Use endpoint names, not URLs
        "home": "home"
    }
    target = request.args.get("target")
    if target in redirect_targets:
        return redirect(url_for(redirect_targets[target]))
    else:
        return jsonify({"message": "Invalid redirect target"}), 400

