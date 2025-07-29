# A multistage docker build 
# Security: .env file containing tpot username and password should not be copied into container,
# mount it at runtime instead.
# In project root: /Honeypot_Attack_Characterization_Data_Engine
#     docker build -t <image-name> .

# Run with a volume containing data folder and mount user-provided .env file:
#     docker run -p 5000:5000 \
#         -v $(pwd)/web_app/data:/app/data \
#         -v $(pwd)/web_app/.env:/app/web_app/.env \
#         <image-name>
#
# For an interactive shell:
#     docker run -p 5000:5000 -it \
#         -v $(pwd)/web_app/data:/app/data \
#         -v $(pwd)/web_app/.env:/app/web_app/.env \
#         <image-name> /bin/bash

#         app# flask run --host=0.0.0.0 --port=5000


# Stage 1: installing dependencies (requirements.txt)
FROM python:3.11-slim AS builder

WORKDIR /app

# Update and install apt updates, install build tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy and install requirements
COPY web_app/requirements.txt .

# setting up virtual environment
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r requirements.txt


# Stage 2: runtime app contaienr
FROM python:3.11-slim

# Add virtual environment to PATH to use python and pip globally
ENV PATH="/opt/venv/bin:$PATH"

# environment variables for the flask app

# entry point:
ENV FLASK_APP=web_app/app.py
# flask environment:
ENV FLASK_ENV=production

WORKDIR /app

# Copy virtual environment created from first builder stage
COPY --from=builder /opt/venv /opt/venv

# Copying app code into container
COPY . .

EXPOSE 5000

# run the server
CMD ["flask", "run", "--host=0.0.0.0"]
