FROM ghcr.io/railwayapp/nixpacks:ubuntu-1727136237

# Install GLIBC and Tcl/Tk
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    && wget http://ftp.gnu.org/gnu/glibc/glibc-2.38.tar.gz \
    && tar -xzf glibc-2.38.tar.gz \
    && cd glibc-2.38 \
    && mkdir build \
    && cd build \
    && ../configure --prefix=/usr \
    && make -j$(nproc) \
    && make install \
    && apt-get install -y tcl tk \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Run the application
CMD ["python", "deepseek_gui_chatbot.py"]