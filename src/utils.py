import time
import functools
import re

class RateLimiter:
    """Global rate limiter to share state across different pipeline instances."""
    def __init__(self, min_interval=6.0):  # Increased to 6.0s (10 RPM) for extreme safety
        self.min_interval = min_interval
        self.last_request_time = time.time() # Start with current time to throttle first call

    def wait(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            wait_time = self.min_interval - elapsed
            # Only print if we're actually waiting a significant amount of time
            if wait_time > 1:
                print(f"--- Throttling: Resting for {wait_time:.1f}s to respect API quota ---")
            time.sleep(wait_time)
        self.last_request_time = time.time()

# Global instance
GEMINI_LIMITER = RateLimiter()

def retry_with_backoff(max_retries=20, initial_delay=12.0):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                GEMINI_LIMITER.wait()
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    err_msg = str(e).lower()
                    if "429" in err_msg or "resource_exhausted" in err_msg or "quota" in err_msg:
                        # Parse suggested retry delay or use exponential backoff
                        wait_seconds = initial_delay * (1.6 ** attempt)
                        
                        match = re.search(r'retry in ([\d\.]+)s', err_msg)
                        if match:
                            wait_seconds = float(match.group(1)) + 2.0 # Add safety buffer
                            
                        print(f"!!! [API Quota] Hit limit. Cooling down for {wait_seconds:.1f}s... (Attempt {attempt+1}/{max_retries})")
                        time.sleep(wait_seconds)
                        # Reset the limiter's last_request_time so we don't double-throttle after a long wait
                        GEMINI_LIMITER.last_request_time = time.time()
                    else:
                        raise e
            raise Exception(f"Max retries ({max_retries}) exceeded for {func.__name__} due to rate limits.")
        return wrapper
    return decorator
