import jwt
   import os
   from dotenv import load_dotenv

   load_dotenv()

   def verifyJsonWebToken(token):
       '''
       Decode the JSON web token passed and return it.
       Raises exceptions if the token is invalid or expired.
       '''
       try:
           # Get the secret key from an environment variable.  This is crucial for security.
           secret = os.environ.get("JWT_SECRET")

           if not secret:
               raise ValueError("JWT_SECRET environment variable not set.")

           # Decode the token using the secret key and specify the algorithm.
           # It's best practice to explicitly specify the algorithm(s) you expect.
           decoded_token = jwt.decode(token, secret, algorithms=["HS256"])  # Use HS256 or other appropriate algorithm

           return decoded_token

       except jwt.ExpiredSignatureError:
           raise Exception("Token has expired")  # Raise a more specific exception

       except jwt.InvalidTokenError:
           raise Exception("Invalid token")  # Raise a more specific exception

       except Exception as e:
           # Catch any other exceptions during decoding and re-raise them.
           raise Exception(f"Error decoding token: {e}")


   # Example Usage
   try:
       token = "your_jwt_token_here"  # Replace with the actual JWT token
       decoded_payload = verifyJsonWebToken(token)
       print("Decoded Payload:", decoded_payload)
       # Access user information from the decoded payload:
       user_id = decoded_payload.get("user_id")
       username = decoded_payload.get("username")
       print(f"User ID: {user_id}, Username: {username}")

   except Exception as e:
       print("Error verifying token:", e)

