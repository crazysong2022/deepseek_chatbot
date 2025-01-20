# Use a Python base image with Tkinter pre-installed
FROM python:3.12

# Set the working directory
WORKDIR /app

# Install Tcl/Tk and other necessary dependencies
RUN apt-get update && apt-get install -y \
    tcl \
    tk \
    python3-tk

# Copy the requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose the application port (if needed)
EXPOSE 5000

# Set the command to run the application
CMD ["python", "deepseek_gui_chatbot.py"]