import os
from canvasapi import Canvas
from dotenv import load_dotenv
import hashlib
import secrets
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

# Canvas API URL and access token (ideally stored securely, e.g., environment variables)
API_URL = os.getenv("CANVAS_API_URL")
API_KEY = os.getenv("CANVAS_API_KEY")  # Consider using a more secure method like KMS

# Input validation function
def validate_course_id(course_id):
    """
    Validates that the course ID is a positive integer.  This helps prevent
    injection attacks if the course_id is used in further operations.
    """
    try:
        course_id = int(course_id)
        if course_id <= 0:
            logging.error(f"Invalid course ID: {course_id}. Course ID must be a positive integer.")
            return None  # Or raise an exception
        return course_id
    except ValueError:
        logging.error(f"Invalid course ID: {course_id}. Course ID must be an integer.")
        return None  # Or raise an exception


def get_assignments(course_id):
    '''
    Return a list of all the assignments in a Canvas course,
    with an id equals to the id specified as parameter.
    '''

    course_id = validate_course_id(course_id)
    if course_id is None:
        return []  # Or raise an exception

    try:
        # Initialize Canvas API
        canvas = Canvas(API_URL, API_KEY)

        # Get the course object
        course = canvas.get_course(course_id)

        # Get all assignments for the course
        assignments = course.get_assignments()

        assignment_list = []
        for assignment in assignments:
            assignment_list.append({
                'id': assignment.id,
                'name': assignment.name,
                'due_at': assignment.due_at,
                'points_possible': assignment.points_possible
            })

        return assignment_list

    except Exception as e:
        logging.exception(f"An error occurred while retrieving assignments for course ID {course_id}: {e}")
        return []  # Or raise the exception, depending on desired behavior


def hash_password(password):
    """Hashes a password using a randomly generated salt."""
    salt = secrets.token_hex(16)  # Generate a 16-byte random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password


def verify_password(stored_salt, stored_hash, password):
    """Verifies a password against a stored hash and salt."""
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash


if __name__ == '__main__':
    # Example usage:
    course_id = 12345  # Replace with a valid course ID
    assignments = get_assignments(course_id)

    if assignments:
        print(f"Assignments for course ID {course_id}:")
        for assignment in assignments:
            print(f"  - {assignment['name']} (ID: {assignment['id']}, Due: {assignment['due_at']}, Points: {assignment['points_possible']})")
    else:
        print(f"No assignments found for course ID {course_id} or an error occurred.")

    # Example password hashing and verification:
    password = "my_secret_password"
    salt, hashed_password = hash_password(password)
    print(f"Salt: {salt}")
    print(f"Hashed password: {hashed_password}")

    is_valid = verify_password(salt, hashed_password, password)
    print(f"Password is valid: {is_valid}")

    is_valid = verify_password(salt, hashed_password, "wrong_password")
    print(f"Password is valid (wrong password): {is_valid}")

