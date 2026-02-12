from celery import Celery

# Celery configuration (replace with your actual settings)
celery_app = Celery('my_app', broker='redis://localhost:6379/0')

@celery_app.task
def delete_file_task(filepath):
    """Background task to delete a file."""
    try:
        os.remove(filepath)
        logging.info(f"File deleted (async): {filepath}")
    except OSError as e:
        logging.error(f"Error deleting file (async): {e}")

@app.route('/deleteImage')
def deleteImage():
    # ... (existing code for filename validation and path construction) ...

    if not os.path.exists(filepath):
        return jsonify({"message": "The file does not exist"}), 404

    # Dispatch the deletion task to Celery
    delete_file_task.delay(filepath)  # Use .delay() to run asynchronously

    return jsonify({"message": "Deletion request submitted. File will be deleted in the background."}), 202  # 202 Accepted

