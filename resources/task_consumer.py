import json
import time
import os
import logging
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Lock

from tests_tree import TestsTree, download_png_by_name, fetch_png_files_from_github, serialize_log_data

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

tasks_dir = f"/tmp/tasks"
inputs_dir = os.path.join(tasks_dir, "inputs")
results_dir = os.path.join(tasks_dir, "results")

# Ensure directories exist
os.makedirs(inputs_dir, exist_ok=True)
os.makedirs(results_dir, exist_ok=True)

lock = Lock()  # Lock to ensure thread-safe file operations

def execute_tests_tree(data):
    tests_tree_files = fetch_png_files_from_github(data["repository"])
    tests_tree_content = download_png_by_name(tests_tree_files, data["tests_tree"])
    tree = TestsTree(workers=data["nodes"])
    tree.load_from_png_content(tests_tree_content)
    
    leaf_logs = tree.evaluate_tree(data["variables"])
    result = serialize_log_data(leaf_logs)
    return result

def publish_result(task_id, result):
    result_data = {
        "id": task_id,
        "result": result
    }
    result_file = os.path.join(results_dir, f"result_{task_id}.json")
    with open(result_file, "w") as file:
        json.dump(result_data, file)
    logging.info(f"Consumer published result: {result_data}")

def process_task(task_file):
    original_task_file_path = os.path.join(inputs_dir, task_file)
    locked_task_file_path = original_task_file_path + ".lock"

    with lock:
        # Rename task file to avoid reprocessing
        if not os.path.exists(original_task_file_path):
            logging.warning(f"Task file {original_task_file_path} does not exist.")
            return
        if os.path.exists(locked_task_file_path):
            logging.warning(f"Task file {locked_task_file_path} already exists.")
            return
        os.rename(original_task_file_path, locked_task_file_path)

    try:
        with open(locked_task_file_path, "r") as file:
            task = json.load(file)
        
        result = execute_tests_tree(task)
        publish_result(task["id"], result)

        # Clean up the locked file after processing
        os.remove(locked_task_file_path)
        logging.info(f"Task {task['id']} processed and file removed.")
    except Exception as e:
        logging.error(f"Error processing task {task_file}: {str(e)}")
        # Restore file if there was an error
        with lock:
            if os.path.exists(locked_task_file_path):
                os.rename(locked_task_file_path, original_task_file_path)

def task_monitor(executor):
    """
    The task monitor runs in the main process and submits tasks to the ProcessPoolExecutor.
    """
    while True:
        task_files = [f for f in os.listdir(inputs_dir) if f.startswith("task_") and not f.endswith(".lock")]

        for task_file in task_files:
            # Submit tasks for parallel processing using ProcessPoolExecutor
            executor.submit(process_task, task_file)

        time.sleep(3)  # Adjust the sleep duration as needed

if __name__ == "__main__":
    # Create the ProcessPoolExecutor in the main process
    with ProcessPoolExecutor() as executor:
        try:
            # Run the task monitor directly in the main process
            task_monitor(executor)
        except KeyboardInterrupt:
            logging.info("Shutting down gracefully.")
            executor.shutdown(wait=True)
