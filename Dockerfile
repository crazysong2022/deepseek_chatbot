# Use a more recent base image
FROM ubuntu:22.04

# Set the working directory
WORKDIR /app

# Install necessary packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    tcl \
    tk

# Copy the application files
COPY . /app/

# Install Python dependencies
RUN python -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install -r requirements.txt

# Continue with the rest of your Dockerfile...