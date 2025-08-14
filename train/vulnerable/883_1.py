import os
import zipfile
import importlib.util
import shutil

def process_uploaded_zip(zip_file_path):
    extract_path = '/tmp/custom_connectors'
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            zip_file.extractall(extract_path)

        for file_name in os.listdir(extract_path):
            if file_name.endswith('.py'):
                file_path = os.path.join(extract_path, file_name)
                spec = importlib.util.spec_from_file_location(f"custom_connector_{file_name}", file_path)
                if spec is None:
                  print(f"Could not load spec from file {file_path}")
                  continue
                custom_connector = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(custom_connector)
    except Exception as e:
        print(f"Error processing zip file: {e}")
    finally:
      if os.path.exists(extract_path):
        shutil.rmtree(extract_path)

def upload_connector(zip_file):
    process_uploaded_zip(zip_file)