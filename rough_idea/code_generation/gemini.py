import google.generativeai as genai
import os
from time import sleep
import re
from config import config
from dotenv import load_dotenv
from google.api_core import retry
from google.api_core.exceptions import (
    ResourceExhausted,
    ServiceUnavailable,
    InvalidArgument,
    InternalServerError,
)

# Load environment variables from .env file
load_dotenv()

os.environ["TOKENIZERS_PARALLELISM"] = "false"


class CodeGenerator():
    def __init__(self, model=config.completion_model) -> None:
        self.model = model
        genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

    def generate_response(self, task_prompt, task_prompt_id):
        model = genai.GenerativeModel(self.model)
        success = False

        while not success:
            try:
                response = model.generate_content(
                    task_prompt,
                    generation_config={
                        "temperature": 0.0,
                        "top_p": 0.1
                    },
                    safety_settings={
                        "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
                        "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
                        "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
                        "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE"
                    }
                )

                if response.parts:
                    success = True
                else:
                    print(f"Empty response for prompt {task_prompt_id}... Retrying...")
                    sleep(5)
                    continue

            except ResourceExhausted:
                print(f"Rate limit exceeded for prompt {task_prompt_id}... Waiting....")
                sleep(65)
                print("...continue")
            except ServiceUnavailable:
                print(f"Service unavailable for prompt {task_prompt_id}... Waiting....")
                sleep(180)
                print("...continue")
            except InternalServerError:
                print(f"Internal server error for prompt {task_prompt_id}... waiting...")
                sleep(65)
                print("...continue")
            except InvalidArgument:
                print(f"Invalid argument for prompt {task_prompt_id}... waiting...")
                sleep(65)
                print("...continue")
            except ValueError:
                print(f"Invalid content for prompt {task_prompt_id}... waiting...")
                sleep(35)
                return "None"
            except Exception as e:
                print(f"Unexpected error for prompt {task_prompt_id}: {str(e)}... waiting...")
                sleep(65)
                print("...continue")

        if response and response.parts:
            return response.text
        else:
            return "None"

    def wrap_request(self, type, msg):
        # Gemini doesn't use role-based messaging like GPT-4, but keeping method for compatibility
        return msg

    def write_code_to_file(self, prompt_task_id, code, output_dir=None):
        """ Writes a given code snippet and its associated prompt to a Python file. """
        print(f"Writing code for {prompt_task_id} to file")
        if output_dir is None:
            output_dir = config.code_output_dir
        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)
        code_blocks = []
        code_blocks = re.findall(r'```python(.*?)```', code, re.DOTALL)
        # check if code_blocks is empty
        if all(not block.strip() for block in code_blocks):
            code_blocks.append(code)

        filename = f"{prompt_task_id}"
        filepath = os.path.join(output_dir, f"{filename}.py")
        print(filepath)
        try:
            f = open(filepath, "w+", encoding='utf-8')
            for block in code_blocks:
                f.write(block.strip() + '\n\n')
            return filepath
        except Exception as e:
            print(f"Failed to write to file: {e}")
