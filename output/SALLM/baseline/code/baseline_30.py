from your_script_name import get_courses  # Replace your_script_name

canvas_url = "YOUR_CANVAS_URL"  # Replace with your Canvas URL
courses = get_courses(canvas_url)

if courses:
    print("Courses:")
    for course in courses:
        print(f"- {course.name} (ID: {course.id})")
else:
    print("No courses found or an error occurred.")

