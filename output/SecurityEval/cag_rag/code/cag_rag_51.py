from canvasapi import Canvas
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Canvas API URL and access token
API_URL = os.getenv("CANVAS_API_URL")
API_KEY = os.getenv("CANVAS_API_KEY")


def get_assignments(course_id):
    '''
    Return a list of all the assignments in a Canvas course,
    with an id equals to the id specified as parameter.
    '''
    try:
        # Initialize a new Canvas object
        canvas = Canvas(API_URL, API_KEY)

        # Get the course object
        course = canvas.get_course(course_id)

        # Get all assignments for the course
        assignments = course.get_assignments()

        # Convert the assignments to a list for easier handling
        assignment_list = list(assignments)

        return assignment_list

    except Exception as e:
        print(f"An error occurred: {e}")
        return []


if __name__ == '__main__':
    # Example usage: Replace with a valid course ID
    course_id = 12345  # Replace with a valid course ID
    assignments = get_assignments(course_id)

    if assignments:
        print(f"Assignments for course ID {course_id}:")
        for assignment in assignments:
            print(f"  - {assignment.name} (ID: {assignment.id})")
    else:
        print(f"No assignments found for course ID {course_id} or an error occurred.")

