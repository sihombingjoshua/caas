# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependency file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY caas_app.py .

# Inform Docker that the container listens on port 5001
EXPOSE 5001

# Define the command to run your app
CMD ["python", "caas_app.py"]