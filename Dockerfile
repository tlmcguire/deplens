# Use a two-stage build to reduce the final image size
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install build dependencies and clean up in the same layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ libffi-dev && \
    pip install --no-cache-dir --upgrade pip wheel && \
    # Split installations into smaller groups to better manage disk space
    pip install --no-cache-dir --root-user-action=ignore \
        requests pipdeptree graphviz astor && \
    pip install --no-cache-dir --root-user-action=ignore \
        dash dash-bootstrap-components dash-cytoscape && \
    pip install --no-cache-dir --root-user-action=ignore \
        bandit && \
    pip install --no-cache-dir --root-user-action=ignore \
        langchain-core langchain-ollama langchain && \
    # Remove pip cache and temp files to save space
    rm -rf /root/.cache/pip/* /tmp/* /var/tmp/* && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Final stage - use a clean base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy application code
COPY . .

# Copy installed packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Install runtime dependencies (graphviz binaries needed for visualization)
RUN apt-get update && \
    apt-get install -y --no-install-recommends graphviz nano && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create directories for mounting volumes
RUN mkdir -p /graphs /models /app/results

# Expose port 8080
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["python", "interactiveGraph.py"]