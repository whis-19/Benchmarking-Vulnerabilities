import time
import random

class MockChannel:
    def __init__(self, message):
        self.message = message
        self.received_message = message
        self.failure_rate = 0.2

    def receive(self):
        time.sleep(random.uniform(0.1, 0.5))
        if random.random() < self.failure_rate:
            raise ConnectionError("Simulated network error")
        return self.received_message

