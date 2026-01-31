from google import genai
import re
import time
from .utils import retry_with_backoff

class SecureCodeGenerationPipeline:
    def __init__(self, api_key):
        self.client = genai.Client(api_key=api_key)
        self.model_id = 'gemini-2.0-flash' # Upgraded for compatibility

    @retry_with_backoff(max_retries=15)
    def generate_code(self, prompt):
        # Strict formatting instruction appended to every request
        strict_prompt = f"{prompt}\n\nIMPORTANT: Output ONLY the requested Python code. Use ```python and ``` delimiters. No preamble, no explanation."
        
        response = self.client.models.generate_content(
            model=self.model_id,
            contents=strict_prompt
        )
        
        text = response.text
        # Strategy 1: Look for ```python ... ```
        code_blocks = re.findall(r'```python\n?(.*?)\n?```', text, re.DOTALL)
        if code_blocks:
            return code_blocks[0].strip()
        
        # Strategy 2: Look for generic ``` ... ```
        code_blocks = re.findall(r'```\n?(.*?)\n?```', text, re.DOTALL)
        if code_blocks:
            return code_blocks[0].strip()
        
        # Strategy 3: Return raw text if it looks like code, otherwise hopefully Strategy 1/2 caught it
        return text.strip()


    def rci_loop(self, task_prompt):
        # Step 1: Initial Generation [cite: 122]
        initial_code = self.generate_code(f"Generate secure Python code for: {task_prompt}")
        # Step 2: Self-Critique [cite: 123]
        critique = self.generate_code(f"Review the following and find security problems: {initial_code}")
        # Step 3: Final Improvement [cite: 124]
        final_code = self.generate_code(f"Based on the critique: {critique}, improve the code: {initial_code}")
        return final_code