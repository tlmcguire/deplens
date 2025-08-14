import os
from wheel import bdist_wheel
import shutil
import sys

def create_wheel(package_name):
    if not package_name:
        raise ValueError("Package name cannot be empty.")

    temp_dir = f"/tmp/{package_name}"
    os.makedirs(temp_dir, exist_ok=True)

    setup_py_content = f"""
from setuptools import setup

setup(
    name='{package_name}',
    version='0.1.0',
    packages=['{package_name}'],
)
"""
    with open(os.path.join(temp_dir, "setup.py"), "w") as f:
      f.write(setup_py_content)

    package_dir = os.path.join(temp_dir, package_name)
    os.makedirs(package_dir, exist_ok=True)
    open(os.path.join(package_dir, "__init__.py"), "a").close()


    dist_dir = os.path.join(temp_dir, "dist")
    wheel_cmd = bdist_wheel.bdist_wheel(dist_dir)

    old_cwd = os.getcwd()
    os.chdir(temp_dir)
    try:
        wheel_cmd.run()
    finally:
        os.chdir(old_cwd)



    wheel_file = None
    for file in os.listdir(dist_dir):
        if file.endswith(".whl"):
            wheel_file = os.path.join(dist_dir, file)
            break

    if wheel_file:
        print(f"Wheel created at {wheel_file}")
    else:
        print("Wheel creation failed")



if __name__ == "__main__":
    user_input = input("Enter the package name: ")
    create_wheel(user_input)