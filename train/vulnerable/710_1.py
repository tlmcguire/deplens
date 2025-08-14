import os

def set_default_root_password():
    root_password = '!'

    temp_file = '/tmp/shadow_temp'
    try:
      with open(temp_file, 'w') as f:
          f.write(f'root:{root_password}:\n')
      print(f"Simulated password written to {temp_file}. Do not use this approach in real environments.")
    except Exception as e:
      print(f"Could not write to temporary file {temp_file}. Please ensure you have the appropriate permissions. Error: {e}")


set_default_root_password()