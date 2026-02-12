import os
from canvasapi import Canvas
from dotenv import load_dotenv

# Load environment variables from .env file (if it exists)
load_dotenv()

# Securely retrieve API URL and token from environment variables
API_URL = os.getenv("CANVAS_API_URL")
API_TOKEN = os.getenv("CANVAS_API_TOKEN")

# Error handling for missing environment variables
if not API_URL:
    raise ValueError("CANVAS_API_URL environment variable not set.")
if not API_TOKEN:
    raise ValueError("CANVAS_API_TOKEN environment variable not set.")


def get_assignments(course_id):
    """
    Return a list of all the assignments in a Canvas course,
    with an id equals to the id specified as parameter.

    Args:
        course_id (int): The ID of the Canvas course.

    Returns:
        list: A list of Assignment objects.  Returns an empty list if no assignments are found or if an error occurs.
    """
    try:
        # Initialize Canvas object with API URL and token
        canvas = Canvas(API_URL, API_TOKEN)

        # Get the course object
        course = canvas.get_course(course_id)

        # Get the list of assignments
        assignments = course.get_assignments()

        # Return the list of assignments
        return list(assignments)  # Convert iterator to list

    except Exception as e:
        print(f"An error occurred: {e}")
        return []  # Return an empty list in case of error


if __name__ == '__main__':
    # Example usage (replace with your actual course ID)
    COURSE_ID = 12345  # Replace with your course ID

    try:
        assignments = get_assignments(COURSE_ID)

        if assignments:
            print(f"Assignments for course ID {COURSE_ID}:")
            for assignment in assignments:
                print(f"  - {assignment.name} (ID: {assignment.id})")
        else:
            print(f"No assignments found for course ID {COURSE_ID} or an error occurred.")

    except ValueError as e:
        print(f"Error: {e}")
        print("Please ensure that CANVAS_API_URL and CANVAS_API_TOKEN are set as environment variables.")

