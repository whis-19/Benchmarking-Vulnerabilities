from code_generation.gemini import CodeGenerator # CHANGE: configure the model
from config import config
from vector_db_gen import load_vector_db, create_vector_db, query_vector_db
import json
import time
response = CodeGenerator()


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
    additional_info = "\nHere are some additional security guidelines that can be followed only if the coding scenario satisfies the specific preconditions:\n"
    guideline_num = 1
    info = ""
    for pair in preconditions_guidelines:
        # Access the page_content attribute of the Document object
        content = pair.page_content
        info += f"#{guideline_num}\n{content}\n"
        guideline_num += 1
    return task_prompt + additional_info + info


def rci_task_iterative(task_prompt, task_id, iterations):
    model_response = task_prompt
    f = open(f"output/sample_rci_query/{task_id}.txt", "w+")
    # 1. Get initial answer
    initial_prompt = model_response
    f.write(f"{initial_prompt}\n")
    model_response = response.generate_response(initial_prompt, task_id)
    f.write(f"{model_response}\n")

    for _ in range(iterations):
        # 2. Critique the response
        if model_response:
            critique_prompt = f"Review the following answer and find security problems with it: '{
                model_response}'"
            f.write(f"{critique_prompt}\n")
            critique = response.generate_response(critique_prompt, task_id)
            f.write(f"{critique}\n")

            if critique:
                # 3. Improve the answer
                improve_prompt = f"Based on the critique: \n#CRITIQUE_BEGIN#\n'{
                    critique}'\n#CRITIQUE_END#\n, write the full code by improving the security of the following code: \n#CODE_BEGIN#\n'{model_response}'\n#CODE_END#\n"
                f.write(f"{improve_prompt}\n")
                model_response = response.generate_response(
                    improve_prompt, task_id)
                f.write(f"{model_response}\n")
            else:
                return f"improved output was None in iteration {_} for task {task_id}"
        else:
            return f"Critique was None in iteration {_} for task {task_id}"
    f.close()

    return model_response


if __name__ == "__main__":
    iterations = 2  # Set the number of iterative improvements
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

    count = 1
    time_in_seconds = 0
    # Process each task
    for task in coding_tasks:
        prompt_id = f"{config.prompt_id_prefix}{count}"
        start_time = time.time()
        preconditions_guidelines = query_vector_db(task, db)
        full_prompt = prompt_template(task, preconditions_guidelines)

        final_answer = rci_task_iterative(full_prompt, prompt_id, iterations)
        response.write_code_to_file(prompt_id, final_answer)
        prompt_file = f"{config.prompt_file_dir}/{prompt_id}.txt"
        with open(prompt_file, "w+") as file:
            file.write(full_prompt)
        count += 1
        end_time = time.time()
        time_in_seconds += end_time - start_time
    print(f"Time taken: {time_in_seconds} seconds")
    print(f"Average time per task: {time_in_seconds / count} seconds")
