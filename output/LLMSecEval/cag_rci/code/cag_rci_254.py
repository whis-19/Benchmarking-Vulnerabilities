from flask import Flask, request, jsonify
        from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity

        app = Flask(__name__)
        app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
        jwt = JWTManager(app)

        @app.route("/login", methods=["POST"])
        def login():
            username = request.json.get("username", None)
            password = request.json.get("password", None)
            # Authenticate user (e.g., check against database - replace with your actual authentication logic)
            if username != "test" or password != "test":
                return jsonify({"msg": "Bad username or password"}), 401

            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token)

        @app.route("/api/is_moderator/<username>")
        @jwt_required()  # Protect the endpoint
        def is_moderator_api(username):
            current_user = get_jwt_identity() # Get the identity of the current user
            # ... your code ...

