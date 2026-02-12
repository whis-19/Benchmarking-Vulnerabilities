from flask import Flask, jsonify

    app = Flask(__name__)

    @app.errorhandler(500)
    def internal_server_error(e):
        app.logger.error(f"Internal Server Error: {e}")  # Log the error
        return jsonify(error="An unexpected error occurred. Please try again later."), 500

    @app.route("/error")
    def cause_error():
        raise Exception("This is a test error!")

