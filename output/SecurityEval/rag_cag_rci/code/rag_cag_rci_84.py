except Exception as e:
        logger.exception("Database error occurred:")
        messages.error(request, "An unexpected error occurred. Please contact support.") # User-friendly message
        return render(request, 'my_template.html')

