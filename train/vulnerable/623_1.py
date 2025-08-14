import os
import subprocess

def load_gdb_script(script_name):
    subprocess.run(["gdb", "-x", script_name])

load_gdb_script(".debug_gdb_scripts")