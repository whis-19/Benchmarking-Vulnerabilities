
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


def rci_task_iterative(task, task_id, iterations):
    model_response = task
    f = open(f"output/sample_rci_query/{task_id}.txt", "w+")
    # 1. Get initial answer
    initial_prompt = model_response
    f.write(f"{initial_prompt}\n")
    model_response = response.generate_response(initial_prompt, task_id)
    f.write(f"{model_response}\n")

    for _ in range(iterations):
        # 2. Critique the response
        if model_response:
            critique_prompt = f"Review the following answer and find security shortcomings with it: '{
                model_response}'"

            critique = response.generate_response(critique_prompt, task_id)
            # print(critique)

            if critique:
                # 3. Improve the answer
                improve_prompt = f"Based on the critique: \n#CRITIQUE_BEGIN#\n'{
                    critique}'\n#CRITIQUE_END#\n, write the full code by improving the following code: \n#CODE_BEGIN#\n'{model_response}'\n#CODE_END#\n"
                f.write(f"{improve_prompt}\n")
                model_response = response.generate_response(
                    improve_prompt, task_id)
                f.write(f"{model_response}\n")
            else:
                return f"improved output was None in iteration {_} for task {task_id}"
        else:
            return f"Critique was None in iteration {_} for task {task_id}"
        # print(model_response)

    f.close()
    return model_response


if __name__ == "__main__":
    iterations = 2  # Set the number of iterative improvements
    # CHANGE: call the right function depending on the dataset to be used
    tasks = read_Sallms_tasks(config.prompt_dataset_file) # for reading the tasks from SALLM
    # tasks = read_SecurityEval_tasks(config.prompt_dataset_file) # for reading the tasks from SecurityEval
    # tasks = read_LLMSecEval_Py(config.prompt_dataset_file) # for reading the tasks from LLMSecEval

    count = 1
    time_in_seconds = 0
    # Process each task
    for task in tasks:
        task_id = f"{config.prompt_id_prefix}{count}"
        task_prompt = f"Generate secure Python code for the following: {task}"
        print(task_prompt)
        try:
            start_time = time.time()
            final_answer = rci_task_iterative(task_prompt, task_id, iterations)
            end_time = time.time()
            time_in_seconds += end_time - start_time
            # response.write_code_to_file(task_id, final_answer)
        except ValueError as e:
            print(f"Error processing task {task_id}: {str(e)}")
            # response.write_code_to_file(task_id, "Empty content")
        count += 1
    print(f"Time taken: {time_in_seconds} seconds")
    print(f"Average time per task: {time_in_seconds / count} seconds")
