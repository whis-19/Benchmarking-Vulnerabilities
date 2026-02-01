from openai import OpenAI
import os
from time import sleep
import re
from config import config
from openai import (
    APIError,
    RateLimitError,
    APIConnectionError,
    InternalServerError
)

os.environ["TOKENIZERS_PARALLELISM"] = "false"


class CodeGenerator():
    def __init__(self, model="gpt-4-1106-preview") -> None:
        self.model = model

    def generate_response(self, task_prompt, task_prompt_id):

        client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        user_task_prompt = self.wrap_request("user", task_prompt)
        msgs = [user_task_prompt]
        success = False
        while not success:
            try:
                # sleep(20)
                response = client.chat.completions.create(
                    model=self.model,
                    messages=msgs,
                    temperature=0.0,
                    top_p=0.1
                )
                success = True
                if "<span " in response:
                    print(f"Access error for prompt {
                          task_prompt_id}... Waiting....")
                    sleep(65)
                    print("...continue...")

            except RateLimitError:
                print(f"RateLimitError for prompt {
                      task_prompt_id},... Waiting....")
                sleep(65)  # wait for 1 min to reset ratelimit
                print("...continue")
            except APIError:
                print(f"API error for prompt {task_prompt_id},... Waiting....")
                sleep(180)  # wait for 1 min to reset ratelimit
                print("...continue")
            except InternalServerError:
                print(f"Serveroverloaded for prompt {
                      task_prompt_id}... waiting...")
                sleep(65)  # wait for 1 min to reset ratelimit
                print("...continue")
            # except client.Timeout:
            #     print(f"Timeout for prompt {task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            except APIConnectionError:
                print(f"API connection error for prompt {
                      task_prompt_id}... waiting...")
                sleep(65)  # wait for 1 min to reset ratelimit
                print("...continue")
            # except client.APITimeoutError:
            #     print(f"API Timeout for prompt {task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            # except client.AuthenticationError:
            #     print(f"Authentication error for prompt {
            #           task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            # except client.BadRequestError:
            #     print(f"Bad request error for prompt {
            #           task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            # except client.ConflictError:
            #     print(f"Conflict for prompt {task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            # except client.InternalServerError:
            #     print(f"Internal server error for prompt {
            #           task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            # except client.NotFoundError:
            #     print(f"Not found error for prompt {
            #           task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            # except client.PermissionDeniedError:
            #     print(f"Permission denied for prompt {
            #           task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            # except client.RateLimitError:
            #     print(f"Rate limit error for prompt {
            #           task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")
            # except client.UnprocessableEntityError:
            #     print(f"Unprocessable entity error for prompt {
            #           task_prompt_id}... waiting...")
            #     sleep(65)  # wait for 1 min to reset ratelimit
            #     print("...continue")

        if response.choices:
            response_content = response.choices[0].message.content
            return response_content
        else:
            return None

    def wrap_request(self, type, msg):
        return {"role": type, "content": msg}

    def write_code_to_file(self, prompt_task_id, code):
        """ Writes a given code snippet and its associated prompt to a Python file. """
        print(f"Writing code for {prompt_task_id} to file")
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
        # filepath = f"{prompt_task_id}.py"
        print(filepath)
        try:
            f = open(filepath, "w+", encoding='utf-8')
            # f.write(f"#Prompt: {prompt}\n")
            for block in code_blocks:
                f.write(block.strip() + '\n\n')
            # f.write(f"{code}\n")  # Adding a newline to separate code snippets
            return filepath
        except Exception as e:
            print(f"Failed to write to file: {e}")
