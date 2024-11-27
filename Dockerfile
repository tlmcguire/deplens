# Image 
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for Graphviz
RUN apt-get update && apt-get install -y graphviz && apt-get clean

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install the required packages
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt

# Copy the rest of your application code into the container
COPY dependencyTree.py .

# Command to run your script
CMD ["python3", "dependencyTree.py"]
