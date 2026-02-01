from code_generation.gemini import CodeGenerator # CHANGE: configure the model
from vector_db_gen import load_vector_db, create_vector_db, query_vector_db
from config import config
import json
import time


def read_LLMSecEval_Py(file_path: str):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        return lines


def read_Sallms_tasks(file_path: str):
    security_eval_tasks = []
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line)
            security_eval_tasks.append(data.get('prompt', '').strip())
    return security_eval_tasks


def read_SecurityEval_tasks(file_path: str):
    security_eval_tasks = []
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line)
            security_eval_tasks.append(data.get('Prompt', '').strip())
    return security_eval_tasks


def prompt_template(task: str, preconditions_guidelines: list[str]):
    task_prompt = f"Generate secure Python code for the following:\n {task}"
    additional_info = "\nHere are some additional security guidelines to follow if the coding task satisfies the specific preconditions:\n"
    guideline_num = 1
    info = ""
    for pair in preconditions_guidelines:
        # Access the page_content attribute of the Document object
        content = pair.page_content
        info += f"#{guideline_num}\n{content}\n"
        guideline_num += 1
    return task_prompt + additional_info + info


def generate_code(full_prompt: str, prompt_id: str):
    code_generator = CodeGenerator()
    code = code_generator.generate_response(full_prompt, prompt_id)
    code_generator.write_code_to_file(prompt_id, code)
    prompt_file = f"{config.prompt_file_dir}/{
        prompt_id}.txt"
    with open(prompt_file, "w") as file:
        file.write(full_prompt)
    return


if __name__ == "__main__":
    # CHANGE: call the right function depending on the dataset to be used
    coding_tasks = read_Sallms_tasks(config.prompt_dataset_file) # for reading the tasks from SALLM
    # coding_tasks = read_SecurityEval_tasks(config.prompt_dataset_file) # for reading the tasks from SecurityEval
    # coding_tasks = read_LLMSecEval_Py(config.prompt_dataset_file) # for reading the tasks from LLMSecEval

    try:
        # Try to load existing database first
        db = load_vector_db()
    except FileNotFoundError:
        # Create new database if none exists
        db = create_vector_db()
    time_in_seconds = 0
    count = 1
    for task in coding_tasks:
        print(f"Generating code for task {count}")
        start_time = time.time()
        prompt_id = f"{config.prompt_id_prefix}{count}"
        preconditions_guidelines = query_vector_db(task, db)
        full_prompt = prompt_template(task, preconditions_guidelines)
        generate_code(full_prompt, prompt_id)
        end_time = time.time()
        time_in_seconds += end_time - start_time
        count += 1
    print(f"Time taken: {time_in_seconds} seconds")
    print(f"Average time per task: {time_in_seconds / count} seconds")
