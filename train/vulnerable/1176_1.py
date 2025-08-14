import os

class Hoverfly:
    def __init__(self, responses_body_files_path):
        self.Cfg = {
            'ResponsesBodyFilesPath': responses_body_files_path
        }

    def create_simulation(self, file_path):
        final_path = os.path.join(self.Cfg['ResponsesBodyFilesPath'], file_path)

        with open(final_path, 'r') as file:
            return file.read()

hoverfly = Hoverfly('/allowed/path')
content = hoverfly.create_simulation('../etc/passwd')
print(content)