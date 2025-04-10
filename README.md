# DepLens

DepLens is a containerized Python tool designed to assist in analyzing dependencies, visualizing code structure, and identifying security vulnerabilities in Python packages.

## Features

- **Interactive Dependency Visualization**: View package dependencies as an interactive graph
- **Security Analysis**: Scan packages for security vulnerabilities using Bandit
- **LLM-Based Security Scanning**: Analyze Python code for vulnerabilities using LLM models
- **AST Visualization**: Explore Abstract Syntax Trees for Python files
- **File Browsing**: Navigate through package source code

## System Requirements

### Hardware Requirements
- Minimum 4GB RAM (8GB recommended for larger packages)
- At least 10GB free disk space
- Any modern CPU with 2+ cores

### Software Requirements
- **Docker**: Version 20.10 or newer
- **Ollama**: Version 0.1.14 or newer
- A modern web browser (Chrome, Firefox, Safari, or Edge)
- Internet connection for initial setup and package downloads

## Installation

### Prerequisites
1. **Install Docker**:
   - [Docker Desktop](https://www.docker.com/products/docker-desktop/) for Windows/Mac
   - [Docker Engine](https://docs.docker.com/engine/install/) for Linux

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

2. **Build the Docker image**:
   ```bash
   docker build -t deplens .
   ```

3. **Run Ollama in a separate terminal**:
   ```bash
   ollama serve
   ```
   The first time you run DepLens, it will automatically download the required LLM model (about 4GB).

4. **Run DepLens**:
   ```bash
   docker run --rm -it -p 8080:8080 --add-host=host.docker.internal:host-gateway \
     -v "$(pwd)/graphs:/graphs" \
     -v "$(pwd)/models:/models" \
     -v "$(pwd)/results:/app/results" \
     deplens
   ```

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

### LLM Security Scanning
The tool uses Ollama to analyze Python code for security issues:
- Opens an AST visualization of selected files
- Identifies vulnerable lines of code and highlights them
- Provides detailed vulnerability reports with remediation suggestions

## Troubleshooting

### Common Issues

1. **Cannot connect to Ollama**:
   - Make sure Ollama is running (`ollama serve` in a separate terminal)
   - Check if the host.docker.internal mapping is correct for your system
   - Verify firewall settings allow communication on port 11434

2. **Web interface not loading**:
   - Confirm port 8080 is not in use by another application
   - Check Docker logs for any startup errors

3. **Analysis takes too long**:
   - Large packages can take significant time to analyze
   - Consider using a more powerful machine for extensive package analysis
   - Check if your disk I/O is a bottleneck