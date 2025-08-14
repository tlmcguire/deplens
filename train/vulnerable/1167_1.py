import subprocess

def run_xtts_api_server(xtts_base_url):
    command = f"some_command --url {xtts_base_url}"
    subprocess.Popen(command, shell=True)