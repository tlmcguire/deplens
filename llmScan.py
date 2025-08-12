from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama.llms import OllamaLLM
import json
import os
import sys
import re
import time

def load_python_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def append_line_numbers(analyzed_json, source_code_path):
    """
    Corrects line numbers in vulnerability analysis by finding the actual line
    where each code snippet appears in the source code.
    """
    with open(source_code_path, 'r') as f:
        source_lines = f.readlines()
    
    # Strip comments and whitespace from source lines for better matching
    cleaned_source_lines = []
    for line in source_lines:
        # Remove the line number comment and trailing whitespace
        cleaned_line = re.sub(r'\s*#\s*line\s+\d+\s*$', '', line).rstrip()
        cleaned_source_lines.append(cleaned_line)
    
    # Process each vulnerability
    for vuln in analyzed_json.get("vulnerabilities", []):
        code_snippet = vuln.get("code_snippet", "").strip()
        if not code_snippet:
            continue
            
        # Search for the code snippet in the source file
        for i, line in enumerate(cleaned_source_lines):
            if code_snippet in line:
                # Line numbers are 1-indexed
                vuln["line_number"] = i + 1
                break
    
    return analyzed_json

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


Return your analysis as a JSON dictionary with the following structure:
```json
{{
  "vulnerable": true/false,
  "vulnerabilities": [
    {{
      "line_number": int,
      "node_type": "Function/Call/Assignment/etc",
      "code_snippet": "vulnerable code here",
      "vulnerability_type": "type of vulnerability",
      "description": "detailed explanation",
      "remediation": "how to fix it"
    }}
  ]
}}
```

</user>
"""

from langchain_ollama import __version__ as ollama_version
print(f"Using langchain_ollama version: {ollama_version}")

# Configure LLM settings from environment variables with defaults
# Try multiple URLs for Ollama connection
OLLAMA_URLS = [
    os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),  # Default to localhost
    "http://host.containers.internal:11434",  # Docker fallback
    "http://127.0.0.1:11434",  # Local fallback
    "http://0.0.0.0:11434"     # Alternative fallback
]
PRIMARY_MODEL = os.environ.get("OLLAMA_PRIMARY_MODEL", "llama3.1:8b")
FALLBACK_MODEL = os.environ.get("OLLAMA_FALLBACK_MODEL", "gemma3:4b")
MAX_RETRIES = int(os.environ.get("OLLAMA_MAX_RETRIES", "3"))
RETRY_DELAY = int(os.environ.get("OLLAMA_RETRY_DELAY", "5"))

def initialize_llm(model_name=None):
    """Initialize the LLM with retries and proper error handling"""
    model_name = model_name or PRIMARY_MODEL
    
    # Try each URL until one works
    for base_url in OLLAMA_URLS:
        retries = 0
        while retries < MAX_RETRIES:
            try:
                print(f"Attempting to initialize LLM with model {model_name} at {base_url}...")
                model = OllamaLLM(
                    model=model_name,
                    temperature=0,
                    base_url=base_url
                )
                # Test the model with a simple request to verify connection
                _ = model.invoke("Test connection")
                print(f"Successfully initialized model: {model_name} at {base_url}")
                return model
            except Exception as e:
                retries += 1
                print(f"Attempt {retries}/{MAX_RETRIES} failed for {base_url}: {str(e)}")
                if retries < MAX_RETRIES:
                    print(f"Retrying in {RETRY_DELAY} seconds...")
                    time.sleep(RETRY_DELAY)
                else:
                    print(f"Failed to connect to {base_url} after {MAX_RETRIES} attempts")
                    break  # Try next URL
    
    raise RuntimeError(f"Failed to initialize LLM with any available URL after {MAX_RETRIES} attempts each")

# Try to initialize with primary model, fall back to alternative if needed
try:
    model = initialize_llm(PRIMARY_MODEL)
except Exception as e:
    print(f"Primary model failed: {e}")
    try:
        print(f"Attempting fallback to {FALLBACK_MODEL}...")
        model = initialize_llm(FALLBACK_MODEL)
    except Exception as e:
        print(f"Fallback model also failed: {e}")
        model = None
        print("WARNING: Running without a working LLM model. Scanning will fail.")

prompt = ChatPromptTemplate.from_template(template)
# Only create chain if model was successfully initialized
chain = prompt | model if model is not None else None

def scan_vulnerabilities(python_code_path):
    """
    Analyzes a Python file for security vulnerabilities.
    
    Args:
        python_code_path (str): Path to the Python file to analyze
        
    Returns:
        tuple: (success, result)
            - success (bool): True if analysis was successful, False otherwise
            - result (dict or str): JSON analysis results if successful, error message if not
    """
    try:
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
        
        json_text = response.strip()
        
        if not json_text.startswith('{') or not json_text.endswith('}'):
            json_match = re.search(r'({[\s\S]*})', json_text)
            if json_match:
                json_text = json_match.group(1)
        
        # Parse the resulting JSON
        analyzed_ast = json.loads(json_text)
        
        # Correct the line numbers based on code snippets
        analyzed_ast = append_line_numbers(analyzed_ast, python_code_path)
        
        return True, analyzed_ast
        
    except FileNotFoundError:
        return False, f"Error: Could not find file at {python_code_path}"
    except json.JSONDecodeError as e:
        return False, f"Failed to parse LLM response as JSON"
    except Exception as e:
        return False, f"Error: {str(e)}"

def get_analysis_filename(python_file_path):
    """
    Generate analysis filename from Python file path.
    Example: /path/to/Example.py -> Example_analysis.json
    """
    base_name = os.path.basename(python_file_path)
    file_name = os.path.splitext(base_name)[0]  # Remove .py extension
    return f"{file_name}_analysis.json"

def clear_results_directory():
    """
    Clear the results directory at startup
    """
    results_dir = os.path.join(os.getcwd(), "results")
    if os.path.exists(results_dir):
        print(f"Clearing results directory: {results_dir}")
        # Remove all files but keep the directory
        for file_name in os.listdir(results_dir):
            file_path = os.path.join(results_dir, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
    else:
        # Create the directory if it doesn't exist
        os.makedirs(results_dir, exist_ok=True)
        print(f"Created results directory: {results_dir}")

# Update the main function to use file-specific output names
def main(python_file_path=None):
    """
    Main function that runs the vulnerability scanner on a Python file.
    
    Args:
        python_file_path (str): Path to the Python file to analyze
    """
    if not python_file_path:
        if len(sys.argv) < 2:
            print("Usage: python llmScan.py <path_to_python_file>")
            return
        python_file_path = sys.argv[1]
    
    print(f"Analyzing Python code for security vulnerabilities: {python_file_path}")
    success, result = scan_vulnerabilities(python_file_path)
    
    if success:
        # Generate file-specific analysis filename
        analysis_filename = get_analysis_filename(python_file_path)
        output_file = os.path.join("results", analysis_filename)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
            
        print(f"Analysis complete. Results saved to {output_file}")
        
        # Count vulnerabilities
        vulns = sum(1 for _ in result.get("vulnerabilities", []))
        if vulns > 0:
            print(f"Found {vulns} potential vulnerabilities")
        else:
            print("✅ Security scan completed: No vulnerabilities detected!")
            # Also ensure the "vulnerable" flag is set to false when no issues found
            if result.get("vulnerable", True):
                result["vulnerable"] = False
                # Update the file with the corrected vulnerable flag
                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
        
        return result
    else:
        print(result)  # Print error message
        return None

# Correct placement of the if __name__ block at module level
if __name__ == "__main__":
    # Clear results directory only when running as a script
    clear_results_directory()
    main()