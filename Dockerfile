# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

    
# Install Python dependencies
RUN pip install --upgrade pip --no-cache-dir
COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir
    
# Copy the Django project into the container
COPY . .

ENTRYPOINT ["sh", "./entrypoint.sh"]

# Expose the port the app runs on
EXPOSE 8000