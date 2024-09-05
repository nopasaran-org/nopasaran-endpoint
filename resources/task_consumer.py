import json
import time
import os
import logging

from tests_tree import TestsTree, download_png_by_name, fetch_png_files_from_github, serialize_log_data

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

tasks_dir = f"/tmp/tasks"
inputs_dir = os.path.join(tasks_dir, "inputs")
results_dir = os.path.join(tasks_dir, "results")

# Ensure directories exist
os.makedirs(inputs_dir, exist_ok=True)
os.makedirs(results_dir, exist_ok=True)

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

def main():
    while True:
        task_files = [f for f in os.listdir(inputs_dir) if f.startswith("task_")]
        for task_file in task_files:
            with open(os.path.join(inputs_dir, task_file), "r") as file:
                task = json.load(file)
            
            result = execute_tests_tree(task)
            publish_result(task["id"], result)
            
            os.remove(os.path.join(inputs_dir, task_file))  # Clean up task file after processing
        
        time.sleep(3)  # Adjust the sleep duration as needed

if __name__ == "__main__":
    main()
