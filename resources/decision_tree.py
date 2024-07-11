import requests
import yaml
import random

class DecisionTree:
    def __init__(self, yaml_content):
        self.tree = yaml.safe_load(yaml_content)
        self.scenarios_repository = self.tree['scenarios_repository']
        self.current_node = self.tree['campaign']

    def predict_next(self, result):
        if 'result' in self.current_node:
            return self.current_node['result']

        if result in self.current_node:
            self.current_node = self.current_node[result]
            if 'result' in self.current_node:
                return self.current_node['result']
            return None
        else:
            raise ValueError(f"Unexpected result '{result}' for test case '{self.current_node['test-case']}'")
        
    def get_next_scenario(self):
        """
        Returns the next scenario which is the concatenation of the scenarios from the scenarios repository and the current node's test case.
        """
        return self.scenarios_repository, self.current_node['test-case']

# Function to fetch the list of YAML files from the GitHub repository
def fetch_yaml_files_from_github(repo_url):
    api_url = repo_url.replace("github.com", "api.github.com/repos") + "/contents"
    response = requests.get(api_url)
    response.raise_for_status()  # Raise an exception for HTTP errors
    files = response.json()
    yaml_files = {file['name']: file['download_url'] for file in files if file['name'].endswith('.yml') or file['name'].endswith('.yaml')}
    return yaml_files

# Function to download the content of a specific YAML file by name
def download_yaml_by_name(yaml_files, file_name):
    if file_name not in yaml_files:
        raise FileNotFoundError(f"No YAML file named '{file_name}' found in the repository.")
    response = requests.get(yaml_files[file_name])
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response.text