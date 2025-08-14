import subprocess

input_data = "![l" * 100000 + "\n"

subprocess.run(["./cmark-gfm", "-e", "autolink"], input=input_data.encode())