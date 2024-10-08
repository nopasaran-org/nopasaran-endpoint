import base64
import datetime
import os
import pickle
import re
import secrets
import threading
import requests
import logging
import random

import pydot
from PIL import Image, PngImagePlugin
from io import BytesIO

from playbooks.master import start_client

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TestsTreeNode:
    def __init__(self, name, num_workers, inputs=None, test=None):
        self.name = name
        self.num_workers = num_workers
        self.inputs = inputs if inputs else [{}] * num_workers
        self.test = test
        self.children = []

    def add_child(self, child, conditions):
        self.children.append((child, conditions))

    def evaluate_test(self, workers, repository, input_values):
        def evaluate_worker(inputs, node, control_node, control_port, repository, results, endpoint_key):
            try:
                execution_logs = execute_test(repository=repository, test=self.test, node=node, control_node=control_node, control_port=control_port, variables=inputs)
                serialized_result_log = extract_base64(execution_logs)
                result = deserialize_log_data(serialized_result_log)
                results[endpoint_key] = result  # Store the result in the shared dictionary

            except Exception as e:
                results[endpoint_key] = e

        threads = []
        results = {}
        control_port = str(random.randint(50000, 60000))

        for i in range(self.num_workers):
            worker_input = input_values[i] if i < len(input_values) else {}

            endpoint_key = f'Worker_{i+1}'

            # Creating a thread for each worker
            thread = threading.Thread(target=evaluate_worker, args=(worker_input, workers[i], workers[(i+1) % self.num_workers], control_port, repository, results, endpoint_key))
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Return the results
        return results 


    def validate_inputs(self, provided_inputs):
        # Validate the inputs for each worker
        for i, input_dict in enumerate(self.inputs):
            worker_key = f'Worker_{i+1}'
            worker_inputs = provided_inputs.get(worker_key, {})
            
            for key, (_, has_default_value) in input_dict.items():
                if not has_default_value and key not in worker_inputs:
                    raise ValueError(f"Missing mandatory input '{key}' for {worker_key} in node '{self.name}'.")

class TestsTree:
    def __init__(self, repository=None, workers=None):
        self.root = None
        self.repository = repository
        self.workers = workers if workers else []
        self._metadata_inputs = {}  # To store inputs metadata temporarily

    def add_root(self, node):
        self.root = node

    def add_edge(self, parent, child, conditions):
        parent.add_child(child, conditions)
    
    def to_dot(self):
        graph = pydot.Dot(graph_type='digraph', bgcolor='white')

        if self.repository:
            repository_label = f'Repository: {self.repository}'
            graph.set_label(repository_label)
            graph.set_labelloc('t')  # Place the label at the top
            graph.set_labeljust('l')  # Left-justify the label

        node_style = {
            'fontname': 'Arial',
            'fontsize': '10',
            'style': 'filled',
            'fillcolor': '#f0f0f0',  # Light gray fill color
            'color': '#666666',  # Border color
        }
        edge_style = {
            'fontsize': '9',
            'fontcolor': '#333333',  # Edge label font color
            'color': '#999999',  # Edge color
        }

        self._add_nodes_edges(self.root, graph, node_style=node_style, edge_style=edge_style)

        return graph

    def from_dot(self, dot_string):
        graph = pydot.graph_from_dot_data(dot_string)[0]
        nodes = {}
        repository_label = graph.get_label()
        if repository_label:
            self.repository = repository_label.replace('Repository: ', '').strip()

        for node in graph.get_nodes():
            name = node.get_name().strip('"')
            label = node.get_attributes()['label'].strip('"').replace('\\n', '\n')
            label_parts = label.split('\n')

            # Initialize variables
            num_workers = 0
            inputs = []
            test = None

            for part in label_parts:
                if part.startswith('#Workers:'):
                    num_workers = int(part.replace('#Workers: ', '').strip())
                elif part.startswith('Inputs (W'):
                    try:
                        encoded_input = node.get_attributes().get('encoded_label')
                        if encoded_input:
                            decoded_input = base64.b64decode(encoded_input).decode()
                            inputs = eval(decoded_input)
                        else:
                            inputs = [{}] * num_workers
                    except Exception as e:
                        logging.error(f"[Tests-Tree] - Error decoding input '{part}': {e}")
                        inputs = [{}] * num_workers
                elif part.startswith('Test: '):
                    test = part.replace('Test: ', '').strip()

            nodes[name] = TestsTreeNode(name, num_workers, inputs, test)

        for edge in graph.get_edges():
            parent_name = edge.get_source().strip('"')
            child_name = edge.get_destination().strip('"')
            try:
                conditions = [base64.b64decode(edge.get_attributes()['encoded_label'].strip('"')).decode()]
            except Exception as e:
                logging.error(f"[Tests-Tree] - Error decoding edge condition: {e}")
                conditions = []
            self.add_edge(nodes[parent_name], nodes[child_name], conditions)

        if nodes:
            self.root = nodes[graph.get_node_list()[0].get_name().strip('"')]

        return self

    def _add_nodes_edges(self, node, graph, node_style=None, edge_style=None):
        if node is None:
            return

        # Construct node label
        node_label = f'{node.name}\n#Workers: {node.num_workers}'
        encoded_inputs = base64.b64encode(str(node.inputs).encode()).decode()

        for i, input_dict in enumerate(node.inputs):
            input_strs = []
            for key, (default_value, has_default_value) in input_dict.items():
                if has_default_value:
                    input_strs.append(f'{key}: {default_value}')
                else:
                    input_strs.append(f'{key}')
            input_str = ', '.join(input_strs)
            node_label += f'\nInputs (W{i+1}): {input_str}'

        if node.test:
            node_label += f'\nTest: {node.test}'

        node_attributes = {
            'label': node_label,
            'shape': 'box',
            'encoded_label': encoded_inputs  # Save encoded inputs
        }

        if node_style:
            node_attributes.update(node_style)

        graph_node = pydot.Node(node.name, **node_attributes)
        graph.add_node(graph_node)
        
        for child, conditions in node.children:
            self._add_nodes_edges(child, graph, node_style, edge_style)
            for condition in conditions:
                edge_attributes = {
                    'label': condition,
                    'fontsize': '9',
                    'fontcolor': '#333333',  # Edge label font color
                    'color': '#999999',  # Edge color
                    'encoded_label': base64.b64encode(condition.encode()).decode()
                }
                if edge_style:
                    edge_attributes.update(edge_style)
                graph.add_edge(pydot.Edge(node.name, child.name, **edge_attributes))


    def evaluate_tree(self, node_inputs=None):
        if node_inputs is None:
            node_inputs = {}

        # Validate all nodes
        self._validate_tree(self.root, node_inputs)

        return self._evaluate_node(self.root, node_inputs)

    def _validate_tree(self, node, node_inputs):
        if node is None:
            return
        
        # Validate inputs for this node
        node.validate_inputs(node_inputs.get(node.name, {}))

        # Validate inputs for child nodes
        for child, _ in node.children:
            self._validate_tree(child, node_inputs)

    def _evaluate_node(self, node, node_inputs):
        # Prepare inputs for each worker, extracting only the values (ignoring the default-value flag)
        worker_inputs = [
            {
                **{k: v for k, (v, has_default_value) in default.items()},  # Only keep the actual value
                **node_inputs.get(node.name, {}).get(f'Worker_{i+1}', {})   # Merge with provided inputs
            }
            for i, default in enumerate(node.inputs)
        ]
        
        # Evaluate the node's test with provided inputs for each worker
        output_values = node.evaluate_test(self.workers, self.repository, worker_inputs)

        # Process children nodes based on conditions
        if node.children:
            for child, conditions in node.children:
                for condition in conditions:
                    try:
                        # Safely evaluate the condition
                        if eval(condition, {}, {'output_values': output_values}):
                            # Recur to evaluate the child node if the condition is met
                            output_values = self._evaluate_node(child, node_inputs)
                            return output_values  # Return as soon as the first condition is met
                    except Exception as e:
                        logging.error(f"[Tests-Tree] - Error evaluating condition '{condition}' for node {node.name}: {e}")

        return output_values

    def save_png_with_metadata(self, filename):
        graph = self.to_dot()
        png_str = graph.create_png()
        image = Image.open(BytesIO(png_str))

        metadata = PngImagePlugin.PngInfo()
        metadata.add_text("TestsTree", graph.to_string())
        metadata.add_text("Repository", self.repository)

        image.save(filename, "PNG", pnginfo=metadata)

    def load_from_png(self, filename):
        image = Image.open(filename)
        metadata = image.info.get("TestsTree")
        repository = image.info.get("Repository")
        if metadata:
            self.from_dot(metadata)
        if repository:
            self.repository = repository

    def load_from_png_content(self, png_content):
        with BytesIO(png_content) as file:
            image = Image.open(file)
            metadata = image.info.get("TestsTree")
            repository = image.info.get("Repository")
            if metadata:
                self.from_dot(metadata)
            if repository:
                self.repository = repository

    def set_node_inputs(self, node_name, inputs):
        # Set inputs for a specific node after loading
        node = self._find_node(self.root, node_name)
        if node:
            # Merge the existing inputs with the new ones
            node.inputs = [
                {**default, **inputs.get(f'Worker_{i+1}', {})}
                for i, default in enumerate(node.inputs)
            ]
        else:
            logging.error(f"[Tests-Tree] - Node '{node_name}' not found.")

    def _find_node(self, node, node_name):
        if node is None:
            return None
        if node.name == node_name:
            return node
        for child, _ in node.children:
            found_node = self._find_node(child, node_name)
            if found_node:
                return found_node
        return None

# Function to fetch the list of PNG files from the GitHub repository
def fetch_png_files_from_github(repo_url):
    api_url = repo_url.replace("github.com", "api.github.com/repos") + "/contents"
    response = requests.get(api_url)
    response.raise_for_status()  # Raise an exception for HTTP errors
    files = response.json()
    png_files = {file['name']: file['download_url'] for file in files if file['name'].endswith('.png')}
    return png_files

# Function to download the content of a specific PNG file by name
def download_png_by_name(png_files, file_name):
    if file_name not in png_files:
        raise FileNotFoundError(f"No PNG file named '{file_name}' found in the repository.")
    response = requests.get(png_files[file_name])
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response.content  # Return the binary content of the PNG file
    
def execute_test(repository, test, node, control_node, control_port, variables):
    # Get the current time and format it as hour-minute-second-day-month-year
    current_time = datetime.datetime.now().strftime("%H-%M-%S-%d-%m-%Y")

    # Create the final output directory by concatenating node name, current time, and a random hex value
    final_output_directory = f"{node}-{current_time}-{secrets.token_hex(3)}"
    
    # Define the paths where the results will be saved
    base_path = f"/tmp/{final_output_directory}"
    test_full_path = f"{base_path}/{test}"
    
    # Create the required directories for saving results
    os.makedirs(test_full_path, exist_ok=True)

    # Prepare the data dictionary to send to the worker
    data = {
        "repository": repository,
        "test_folder": test,
        "control_node": control_node,
        "variables": variables,
        "control_port": control_port
    }

    # Call the start_client function to connect to the worker node and execute the test
    logging.info(f"Starting the client to connect to the worker node {node} and execute the test for {repository}")

    try:
        # Use the node (worker server) as the host for the connection
        log_content = start_client(node, 1957, data)
    except Exception as e:
        logging.error(f"An error occurred while executing the test: {e}")
        return ""
    
    # Now save the log file content to the appropriate directory
    if log_content:
        # Copy the log to the final results directory
        final_log_dir = f"/results/{final_output_directory}"
        os.makedirs(final_log_dir, exist_ok=True)
        final_log_path = f"{final_log_dir}/conf.log"
        
        # Save the log file in the final output directory
        with open(final_log_path, 'w') as final_log_file:
            final_log_file.write(log_content)
        
        return log_content
    else:
        logging.warning("No log content received.")
        return ""    
    
def extract_base64(log_string):
    # Regex pattern to match the base64 encoded string
    base64_pattern = r'(?<=\[Result\] )(\S+)'
    
    # Search for the base64 pattern in the log string
    match = re.search(base64_pattern, log_string)
    
    # If a match is found, return the base64 string
    if match:
        return match.group(1)
    else:
        return None
    
def serialize_log_data(log_data):
    def serialize_object(obj):
        try:
            # Serialize the object to a byte stream
            byte_stream = pickle.dumps(obj)
            # Encode the byte stream to a base64 string
            base64_string = base64.b64encode(byte_stream).decode('utf-8')
            return base64_string
        except Exception as e:
            return None

    def serialize_value(value):
        if value is None:
            return None
        if isinstance(value, dict):
            return {k: serialize_value(v) for k, v in value.items()}
        return serialize_object(value)
    
    serialized_data = {k: serialize_value(v) for k, v in log_data.items()}
    # Encode the final serialized data into a base64 string
    return base64.b64encode(pickle.dumps(serialized_data)).decode('utf-8')
    
def deserialize_log_data(base64_data):
    def deserialize_object(base64_string):
        try:
            # Decode the base64 string to a byte stream
            byte_stream = base64.b64decode(base64_string)
            # Deserialize the byte stream to the original object
            obj = pickle.loads(byte_stream)
            return obj
        except Exception as e:
            return None

    def deserialize_value(value):
        if value is None:
            return None
        if isinstance(value, dict):
            return {k: deserialize_value(v) for k, v in value.items()}
        return deserialize_object(value)
    
    try:
        # Decode the base64 data to a byte stream
        byte_stream = base64.b64decode(base64_data)
        # Deserialize the byte stream to the serialized data
        serialized_data = pickle.loads(byte_stream)
        return {k: deserialize_value(v) for k, v in serialized_data.items()}
    except Exception as e:
        return None
    
def deserialize_log_data(base64_data):
    def deserialize_object(base64_string):
        try:
            # Decode the base64 string to a byte stream
            byte_stream = base64.b64decode(base64_string)
            # Deserialize the byte stream to the original object
            obj = pickle.loads(byte_stream)
            return obj
        except Exception as e:
            return None

    def deserialize_value(value):
        if value is None:
            return None
        if isinstance(value, dict):
            return {k: deserialize_value(v) for k, v in value.items()}
        return deserialize_object(value)
    
    try:
        # Decode the base64 data to a byte stream
        byte_stream = base64.b64decode(base64_data)
        # Deserialize the byte stream to the serialized data
        serialized_data = pickle.loads(byte_stream)
        return {k: deserialize_value(v) for k, v in serialized_data.items()}
    except Exception as e:
        return None    