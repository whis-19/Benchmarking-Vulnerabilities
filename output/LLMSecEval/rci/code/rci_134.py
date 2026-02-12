import logging
import sys
import logging.handlers

def get_valid_index(vehicles):
    """Prompts the user for a vehicle index and validates it."""
    while True:
        try:
            index_str = input("Enter the index of the vehicle you want to view: ")
            index_str = index_str.strip()

            if len(index_str) > 10:
                print("Input too long. Please enter a smaller index.")
                continue

            if not index_str.isdigit():
                print("Invalid input. Please enter a non-negative integer.")
                continue

            index = int(index_str)

            if index < 0:
                print("Invalid input. Please enter a non-negative integer.")
                continue

            if index >= len(vehicles):
                print(f"Index out of range. Please enter an index between 0 and {len(vehicles) - 1}.")
                continue

            return index

        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except Exception as e:
            logging.exception("An unexpected error occurred during index validation:")
            print("An unexpected error occurred. Please try again later.")
            return None  # Or raise the exception if appropriate


def get_vehicle_at_index(vehicles):
    """
    Prompts the user for a vehicle index, validates it, and prints the vehicle at that index.

    Args:
        vehicles: A list of vehicle objects (e.g., strings, dictionaries, or custom objects).
    """

    # Configure logging
    log_file = "vehicle_app.log"
    log_level = logging.ERROR
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Rotating file handler for log rotation
    log_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=1024 * 1024,  # 1 MB
        backupCount=5,  # Keep 5 backup files
        encoding='utf8'
    )
    log_handler.setFormatter(log_formatter)

    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    logger.addHandler(log_handler)


    index = get_valid_index(vehicles)

    if index is None:
        return  # Exit if index validation failed

    try:
        print(f"Vehicle at index {index}: {vehicles[index]}")

    except IndexError:
        logger.error("IndexError occurred despite validation.  Possible race condition or bug.")
        print("An unexpected error occurred. Please try again later.")
    except TypeError as e:
        logger.exception(f"Unexpected data type in the vehicles list: {e}")
        print("An unexpected error occurred. Please try again later.")
    except Exception as e:
        logger.exception("An unexpected error occurred:")
        print("An unexpected error occurred. Please try again later.")


# Example usage:
if __name__ == "__main__":
    # Example vehicle list (replace with your actual vehicle data)
    vehicles = [
        "Toyota Camry",
        "Honda Civic",
        "Ford F-150",
        "Tesla Model 3",
        "Chevrolet Silverado"
    ]

    get_vehicle_at_index(vehicles)

