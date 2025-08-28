#!/usr/bin/env python3
"""
LLM Security Bechmark
This script is designed to measure the ability of LLMs to identify safe and unsafe code.
"""

from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama.llms import OllamaLLM
import json
import os
import sys
import re
import time
import pandas as pd
from llmScan import *


results = []

template = """<system>You are a security vulnerability analyzer for Python code.</system>

<user>
Examples of security vulnerabilities include:
- Unsafe use of untrusted input (e.g., from `request.args`, `request.form`, environment variables, external files)
- Dangerous function calls (e.g., `eval`, `exec`, `os.system`, `subprocess.run`, `pickle.loads`, `yaml.load`)
- Insecure file handling (e.g., `open` or `send_file` with user-controlled paths)
- Cryptographic mistakes (e.g., hardcoded keys, insecure algorithms)
- Web-specific issues (e.g., Cross-Site Scripting (XSS), CSRF vulnerabilities, Open Redirects)
- Hardcoded secrets (e.g., API keys, passwords, tokens)
- Misconfigurations (e.g., exposing debug mode, bad CORS policies)

Analyze this Python code for security vulnerabilities:

```python
{python_code}
```


Return your analysis as a single boolean value: True if vulnerable and False if safe
```

</user>
"""

def test_vulnerabilities(python_code_path):
    """
    Analyzes a Python file for security vulnerabilities

    Args:
        python_code_path (str): Path to the Python file to analyze

    Returns:
        tuple: (success, result)
            - success (bool): True if analysis successful, False otherwise
            - result (bool): True if vulnerable, False if safe
    """

    try:
        # Get model and chain (via lazy initialization)
        model, chain = get_model_and_chain()

        # Check if LLM is available
        if chain is None:
            return False, "Error: No working LLM model available"
        
        # Load Python code
        python_code = load_python_file(python_code_path)

        # Invoke the chain with retries 
        retries = 0
        while retries < MAX_RETRIES:
            try:
                response = chain.invoke({"python_code": python_code})
                break
            except Exception as e:
                retries += 1
                error_msg = f"LLM invocation failed (attempt {retries}/{MAX_RETRIES}): {str(e)}"
                print(error_msg)
                if retries >= MAX_RETRIES:
                    return False, error_msg
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
        

        if isinstance(response, bool):
            return True, response # Return success and boolean value

        else: 
            print("Response is not a boolean value")
            return False, "Error: Response is not a boolean value"
        


    except Exception as e:
        return False, f"An error occurred: {str(e)}"
    

