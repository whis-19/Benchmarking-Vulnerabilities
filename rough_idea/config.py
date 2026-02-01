import yaml
from pathlib import Path


class Config:
    def __init__(self, config_path="config.yaml"):
        # Get the directory containing this script
        current_dir = Path(__file__).parent

        # Load the config file
        with open(current_dir / config_path, 'r') as f:
            self.config = yaml.safe_load(f)

    @property
    def guidelinescsv_file(self):
        return self.config['paths']['guidelinescsv_file']

    @property
    def persist_dir(self):
        return self.config['paths']['persist_dir']

    @property
    def code_output_dir(self):
        return self.config['paths']['code_output_dir']

    @property
    def prompt_dataset_file(self):
        return self.config['paths']['prompt_dataset_file']

    @property
    def embedding_model(self):
        return self.config['models']['embedding_model']

    @property
    def completion_model(self):
        return self.config['models']['completion_model']

    @property
    def prompt_id_prefix(self):
        return self.config['misc']['prompt_id_prefix']

    @property
    def prompt_file_dir(self):
        return self.config['paths']['prompt_file_dir']


# Create a global config instance
config = Config()
