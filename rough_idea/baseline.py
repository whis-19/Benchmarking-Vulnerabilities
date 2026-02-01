from code_generation.gemini import CodeGenerator # CHANGE: configure the model
from config import config
import json
import time

response = CodeGenerator()


def read_SecurityEval_tasks(file_path: str):
    security_eval_tasks = []
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line)
            security_eval_tasks.append(data.get('Prompt', '').strip())
    return security_eval_tasks


def read_Sallms_tasks(file_path: str):
    security_eval_tasks = []
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line)
            security_eval_tasks.append(data.get('prompt', '').strip())
    return security_eval_tasks


def read_LLMSecEval_Py(file_path: str):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        return lines


if __name__ == "__main__":
     # CHANGE: call the right function depending on the dataset to be used
    tasks = read_Sallms_tasks(config.prompt_dataset_file) # for reading the tasks from SALLM
    # tasks = read_SecurityEval_tasks(config.prompt_dataset_file) # for reading the tasks from SecurityEval
    # tasks = read_LLMSecEval_Pyea(config.prompt_dataset_file) # for reading the tasks from LLMSecEval

    count = 1
    time_in_seconds = 0
    # Process each task
    for task in tasks:
        task_id = f"{config.prompt_id_prefix}{count}"
        task_prompt = f"Generate secure Python code for the following: {task}"
        print(task_prompt)
        try:
            start_time = time.time()
            final_answer = response.generate_response(task_prompt, task_id)
            end_time = time.time()
            time_in_seconds += end_time - start_time
            response.write_code_to_file(task_id, final_answer)
        except ValueError as e:
            print(f"Error processing task {task_id}: {str(e)}")
            response.write_code_to_file(task_id, "None")
        count += 1
    print(f"Time taken: {time_in_seconds} seconds")
    print(f"Average time per task: {time_in_seconds / count} seconds")
