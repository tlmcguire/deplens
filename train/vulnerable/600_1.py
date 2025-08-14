import subprocess

def unsafe_script_invoke(script):
    try:
        subprocess.run(script, shell=True, check=True, executable='/bin/bash')
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
    except Exception as e:
         print(f"An unexpected error occurred: {e}")



user_input_script = "ls"
unsafe_script_invoke(user_input_script)