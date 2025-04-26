# Image 
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt file into the container
COPY requirements.txt .
COPY . .

# Install the required packages
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt

# Expose port 8080
EXPOSE 8080

# Command to run your script
CMD ["python", "interactiveGraph.py"]