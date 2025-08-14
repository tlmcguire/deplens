import subprocess

def run_rdf_tool(tool_name):
    allowed_tools = ['safe_tool1', 'safe_tool2', 'safe_tool3']

    if tool_name not in allowed_tools:
        raise ValueError("Unauthorized tool name.")

    subprocess.run(['python', '-m', tool_name], cwd='/path/to/safe/directory')