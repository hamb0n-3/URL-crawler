# Use a slim Python 3.9 image as the base for smaller size and security
FROM python:3.9-slim

# Set environment variables to prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker cache for dependencies
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY crawler.py ./

# Set the default command to show help (so running the container with no args is safe)
ENTRYPOINT ["python", "crawler.py"]
# To pass arguments, use: docker run ... <start_url> [options] 