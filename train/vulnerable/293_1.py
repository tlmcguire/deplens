
import yaml

def load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.load(file, Loader=yaml.FullLoader)

if __name__ == "__main__":
    try:
        data = load_yaml('example.yaml')
        print(data)
    except FileNotFoundError:
        print("Error: example.yaml not found.")

