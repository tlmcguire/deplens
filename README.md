# DepLens

DepLens is a containerized Python tool designed to assist in analyzing dependencies, visualizing code structure, and identifying security vulnerabilities in Python packages.

## Features

- **Interactive Dependency Visualization**: View package dependencies as an interactive graph
- **Security Analysis**: Scan packages for security vulnerabilities using Bandit
- **LLM-Based Security Scanning**: Analyze Python code for vulnerabilities using LLM models
- **AST Visualization**: Explore Abstract Syntax Trees for Python files with export options (PNG, JPG, SVG)
- **File Browsing**: Navigate through package source code
- **Package Testing Tools**: Download, modify, and analyze packages for security testing

### Software Requirements
- **Podman**: Version 4.0 or newer
- **Ollama**: Version 0.1.14 or newer 
- A modern web browser (Firefox, Safari, Chrome)
- Internet connection for initial setup and package downloads

## Installation

### Prerequisites
1. **Install Podman**:
   - [Podman Desktop](https://podman-desktop.io/) for Windows/Mac
   - [Podman Engine](https://podman.io/getting-started/installation) for Linux

2. **Install Ollama**:
   - Download from [ollama.ai](https://ollama.ai/download)
   - Make sure port 11434 is accessible (default Ollama port)

3. **Port Requirements**:
   - Port 8080 needs to be available for the web interface
   - Port 11434 for Ollama LLM communication

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/deplens.git
   cd deplens
   ```

2. **Build the Podman image**:
   ```bash
   podman build -t deplens .
   ```

3. **Run Ollama in a separate terminal**:
   ```bash
   ollama serve
   ```
   
   DepLens requires LLM models to perform LLM-based security analysis.

4. **Run DepLens**:
   ```bash
   podman run --rm -it -p 8080:8080 --add-host=host.containers.internal:host-gateway \
     -v "$(pwd)/graphs:/graphs" \
     -v "$(pwd)/models:/models" \
     -v "$(pwd)/results:/app/results" \
     deplens [package_name]
   ```
   - Optionally specify a package name (defaults to Django if not provided)
   - Use `--skip-download` flag to skip downloading packages (use existing files)

5. Open your browser and navigate to `http://localhost:8080`

## Usage Guide

### Interactive Dependency Graph
- The main view displays dependencies as an interactive graph
- Click on a package node to view its details
- Use the tabs to switch between package details and file structure

### Security Analysis
- Click "Run Bandit Security Analysis" to scan packages for vulnerabilities
- Vulnerable packages will be highlighted with red borders
- Secure packages will have green borders

### Code Exploration
- Navigate through package files in the "Files" tab
- Click on Python files to view their AST (Abstract Syntax Tree)
- In the AST view, click "Run LLM Security Analysis" to detect code vulnerabilities
- Export AST visualizations as PNG, JPG, or SVG for documentation

### LLM Security Scanning
The tool uses Ollama to analyze Python code for security issues:
- Opens an AST visualization of selected files
- Identifies vulnerable lines of code and highlights them
- Provides detailed vulnerability reports with remediation suggestions

### Package Testing Workflow

For testing specific package versions or modifying code before analysis:

1. **Start Podman container in interactive mode**:
   ```bash
   podman run --rm -it -p 8080:8080 --add-host=host.containers.internal:host-gateway \
     -v "$(pwd)/graphs:/graphs" \
     -v "$(pwd)/models:/models" \
     -v "$(pwd)/results:/app/results" \
     --entrypoint /bin/bash \
     deplens
   ```

2. **Download and extract a package**:
   ```bash
   python setupPackage.py <package_name>==<version>
   ```

3. **Modify the package source code as needed**

4. **Run analysis with modified code**:
   ```bash
   python interactiveGraph.py --skip-download <package_name>==<version>
   ```

## Troubleshooting

### Common Issues

1. **Cannot connect to Ollama**:
   - Make sure Ollama is running (`ollama serve` in a separate terminal)
   - Check if the host.containers.internal mapping is correct for your system
   - Verify firewall settings allow communication on port 11434

2. **Web interface not loading**:
   - Confirm port 8080 is not in use by another application
   - Check Podman logs for any startup errors

3. **Analysis takes too long**:
   - Large packages can take significant time to analyze
   - Consider using a more powerful machine for extensive package analysis
   - Check if your disk I/O is a bottleneck

4. **LLM analysis fails**:
   - Verify Ollama has downloaded the required models
   - The tool will attempt to use a fallback model if the primary model fails
   - Check system memory

## Migration from Docker

This project has been migrated from Docker to Podman. If you were previously using Docker, see `PODMAN_MIGRATION.md` for detailed migration information and troubleshooting tips.