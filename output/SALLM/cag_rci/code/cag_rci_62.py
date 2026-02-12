import logging

logging.basicConfig(level=logging.ERROR)  # Configure logging

@app.route("/team/show", methods=["GET"])
def show_team():
    # ...
    if not team_name:
        logging.error("Missing team_name parameter.  Request URL: %s", request.url)
        return "Error: team_name parameter is missing.", 400
    # ...

