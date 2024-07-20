import os
import subprocess
import secrets
import threading

import pydot
import random
from PIL import Image, PngImagePlugin
from io import BytesIO
import requests

class DecisionTreeNode:
    def __init__(self, name, inputs=None, outputs=None, test=None, default_input_values=None):
        self.name = name
        self.inputs = inputs if inputs else []
        self.outputs = outputs if outputs else []
        self.test = test
        self.children = []
        self.default_input_values = default_input_values if default_input_values else {}

    def add_child(self, child, conditions):
        self.children.append((child, conditions))



    def evaluate_test(self, endpoints, repository, input_values):
        def evaluate_endpoint(inputs, endpoint, result_container, is_first_thread):
            # Here you can place your actual evaluation logic
            # For now, just print the inputs and simulate some computation
            result = [str(random.randint(1, 20)) for _ in self.outputs]
            
            # Store the result if this is the first thread
            if is_first_thread:
                result_container['result'] = result
        
        try:
            # Create dictionaries for the inputs for each endpoint
            inputs_endpoint1 = {key: values[0] for key, values in input_values.items()}
            inputs_endpoint2 = {key: values[1] for key, values in input_values.items()}
            
            # Shared container for storing the result of the first thread
            result_container = {}
            
            # Create threads for each endpoint evaluation
            thread1 = threading.Thread(target=evaluate_endpoint, args=(inputs_endpoint1, endpoints[0], result_container, True))
            thread2 = threading.Thread(target=evaluate_endpoint, args=(inputs_endpoint2, endpoints[1], result_container, False))
            
            # Start the threads
            thread1.start()
            thread2.start()
            
            # Wait for both threads to complete
            thread1.join()
            thread2.join()
            
            # Return the result of the first thread
            return result_container.get('result', [])
            
        except AttributeError:
            print(f"Unknown test '{self.test}' for node {self.name}")
            return []
        
class DecisionTree:
    def __init__(self, repository=None, endpoints=None):
        self.root = None
        self.repository = repository
        self.endpoints = endpoints if endpoints else []

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

        # Extract repository from graph label
        repository_label = graph.get_label()
        if repository_label:
            self.repository = repository_label.replace('Repository: ', '').strip()

        for node in graph.get_nodes():
            name = node.get_name().strip('"')
            inputs = []
            outputs = []
            test = None
            default_input_values = {}

            # Parse the label to extract inputs, outputs, and test
            label = node.get_attributes()['label'].strip('"')
            label_parts = label.split('\\n')
            main_label = label_parts[0]

            for part in label_parts[1:]:
                if part.startswith('Inputs: ['):
                    inputs_str = part.replace('Inputs: [', '').replace(']', '')
                    inputs = [inp.split('=')[0].strip() for inp in inputs_str.split(',')]
                    default_input_values = {inp.split('=')[0].strip(): int(inp.split('=')[1].strip()) for inp in inputs_str.split(',') if '=' in inp}
                elif part.startswith('Outputs: '):
                    outputs_str = part.replace('Outputs: ', '').replace("[", "").replace("]", "")
                    outputs = outputs_str.split(', ')
                elif part.startswith('Test: '):
                    test = part.replace('Test: ', '').strip()

            nodes[name] = DecisionTreeNode(name, inputs, outputs, test, default_input_values)

        for edge in graph.get_edges():
            parent_name = edge.get_source().strip('"')
            child_name = edge.get_destination().strip('"')
            conditions = [edge.get_attributes()['label'].strip('"')]
            self.add_edge(nodes[parent_name], nodes[child_name], conditions)

        if nodes:
            self.root = nodes[graph.get_node_list()[0].get_name().strip('"')]

        return self

    def _add_nodes_edges(self, node, graph, parent_default_inputs=None, node_style=None, edge_style=None):
        if node is None:
            return
        
        if parent_default_inputs:
            node_default_inputs = {**parent_default_inputs, **node.default_input_values}
        else:
            node_default_inputs = node.default_input_values
        
        formatted_inputs = self._format_inputs(node.inputs, node_default_inputs)
        default_inputs_str = ', '.join(formatted_inputs) if formatted_inputs else ''
        
        # Use node's name instead of label for node_label
        node_label = f'{node.name}'
        if default_inputs_str:
            node_label += f'\nInputs: [{default_inputs_str}]'
        if node.outputs:
            node_label += f'\nOutputs: [{", ".join(node.outputs)}]'
        if node.test:
            node_label += f'\nTest: {node.test}'
        
        node_attributes = {
            'label': node_label,
            'shape': 'box'
        }

        if node_style:
            node_attributes.update(node_style)

        graph_node = pydot.Node(node.name, **node_attributes)
        graph.add_node(graph_node)
        
        for child, conditions in node.children:
            self._add_nodes_edges(child, graph, node_default_inputs, node_style, edge_style)
            for condition in conditions:
                edge_attributes = {
                    'label': condition,
                    'fontsize': '9',
                    'fontcolor': '#333333',  # Edge label font color
                    'color': '#999999'  # Edge color
                }
                if edge_style:
                    edge_attributes.update(edge_style)
                graph.add_edge(pydot.Edge(node.name, child.name, **edge_attributes))

    def _format_inputs(self, inputs, default_inputs):
        formatted_inputs = []
        for inp in inputs:
            if inp in default_inputs:
                formatted_inputs.append(f'{inp}={default_inputs[inp]}')
            else:
                formatted_inputs.append(inp)
        return formatted_inputs

    def evaluate_tree(self, node_inputs=None):
        if node_inputs is None:
            node_inputs = {}
        return self._evaluate_node(self.root, node_inputs)

    def _evaluate_node(self, node, node_inputs):
        if node.name in node_inputs:
            merged_input_values = {**node.default_input_values, **node_inputs[node.name]}
        else:
            merged_input_values = node.default_input_values

        output_values = node.evaluate_test(self.endpoints, self.repository, merged_input_values)
        for idx, output_name in enumerate(node.outputs):
            merged_input_values[output_name] = output_values[idx]

        if node.children:
            for child, conditions in node.children:
                condition_evaluated = False
                for condition in conditions:
                    try:
                        if eval(condition, {}, merged_input_values):  # Use eval with a safe context
                            output_values = self._evaluate_node(child, node_inputs)
                            condition_evaluated = True
                            break
                    except Exception as e:
                        print(f"Error evaluating condition '{condition}' for node {node.name}: {e}")

                if condition_evaluated:
                    break

        return output_values

    def save_png_with_metadata(self, filename):
        graph = self.to_dot()
        png_str = graph.create_png()
        image = Image.open(BytesIO(png_str))

        metadata = PngImagePlugin.PngInfo()
        metadata.add_text("DecisionTree", graph.to_string())
        metadata.add_text("Repository", self.repository)

        image.save(filename, "PNG", pnginfo=metadata)

    def load_from_png(self, filename):
        image = Image.open(filename)
        metadata = image.info.get("DecisionTree")
        repository = image.info.get("Repository")
        if metadata:
            self.from_dot(metadata)
        if repository:
            self.repository = repository

    def load_from_png_content(self, png_content):
        with BytesIO(png_content) as file:
            image = Image.open(file)
            metadata = image.info.get("DecisionTree")
            repository = image.info.get("Repository")
            if metadata:
                self.from_dot(metadata)
            if repository:
                self.repository = repository

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



def execute_scenario(repository="", test="", node="", control_node="", variables=""):
    try:
        final_output_directory = secrets.token_hex(6)

        # Execute the Ansible playbook for the campaign
        result = subprocess.run(
            [
                "ansible-playbook",
                "/ansible/remote_scenario.yml",
                "-i",
                f"{node}:1963,",
                "--extra-vars",
                f'{{"github_repo_url":"{repository}", "scenario_folder":"{test}", "final_output_directory":"{final_output_directory}", "remote_control_channel_end":"{control_node}", "variables":{variables}}}',
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Find log files in the specified directory tree
        log_contents = []
        for root, dirs, files in os.walk(f"/results/{final_output_directory}"):
            for file in files:
                if file.startswith("conf") and file.endswith(".log"):
                    log_file_path = os.path.join(root, file)
                    with open(log_file_path, 'r') as log_file:
                        log_contents.append(log_file.read())

        return f"+ {', '.join(log_contents)}"  # Join log contents with a comma or any other separator
    except Exception as e:
        return f"- {str(e)}"