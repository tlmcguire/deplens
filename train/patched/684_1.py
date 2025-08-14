required_dependencies = [
    'numpy',
    'scipy',
    'matplotlib',
]

def install_dependencies(dependencies):
    import subprocess
    import sys

    for package in dependencies:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

install_dependencies(required_dependencies)