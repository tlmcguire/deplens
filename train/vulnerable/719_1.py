import subprocess

def upload_and_execute_script(script_content):


    try:
        with open("temp_script.py", "w") as f:
            f.write(script_content)

        process = subprocess.Popen(["python", "temp_script.py"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            print("Script executed successfully:")
            print(stdout.decode())
        else:
            print("Script execution failed:")
            print(stderr.decode())
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
      import os
      if os.path.exists("temp_script.py"):
        os.remove("temp_script.py")

user_uploaded_script = """
import os
print(os.system('whoami'))  # This could execute arbitrary commands, but here we print its output
"""

upload_and_execute_script(user_uploaded_script)