import json
import os
import logging

from services.netbird_service import get_netbird_ip

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

tasks_dir = f"/tasks"
inputs_dir = os.path.join(tasks_dir, "inputs")
results_dir = os.path.join(tasks_dir, "results")

def init_publisher():
    # Ensure directories exist
    os.makedirs(inputs_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    
def complete_task_variables(variables, task_id):
    # Get the top-level key (it could be any, so we just take the first one)
    top_key = next(iter(variables))
    
    # Iterate over each worker in the top-level key
    for _, worker_data in variables[top_key].items():
        # Add the new key-value pairs to each worker
        worker_data['id'] = task_id
        worker_data['signaling-server'] = get_netbird_ip()
        worker_data['signaling-port'] = 1963

    return variables    
    
def publish_task(task_id, repository, tests_tree, nodes, variables):
    try:
        task = {
            "id": task_id,
            "repository": repository,
            "tests_tree": tests_tree,
            "nodes": nodes,
            "variables": complete_task_variables(variables, task_id)
        }
        task_file = os.path.join(inputs_dir, f"task_{task_id}.json")
        with open(task_file, "w") as file:
            json.dump(task, file)
        logging.info(f"Task {task_id} published successfully.")
    except Exception as e:
        logging.error(f"Error publishing task: {e}")
        raise


def read_results():
    results_files = [f for f in os.listdir(results_dir) if f.startswith("result_")]
    results = []
    for result_file in results_files:
        with open(os.path.join(results_dir, result_file), "r") as file:
            results.append(json.load(file))
        os.remove(os.path.join(results_dir, result_file))  # Clean up results file after reading
    return results