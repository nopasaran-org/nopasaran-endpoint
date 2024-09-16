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
    
def publish_task(task_id, repository, tests_tree, nodes, variables):
    variables['id'] = task_id
    variables['signaling-server'] = get_netbird_ip()
    variables['signaling-port'] = 1963
    try:
        task = {
            "id": task_id,
            "repository": repository,
            "tests_tree": tests_tree,
            "nodes": nodes,
            "variables": variables
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