# Makefile: Builds and runs a non-interactive honeypot app container. To start the app: make all. When you're done, make stop.

IMAGE_NAME := flask-honeypot-app
CONTAINER_NAME := flask-honeypot-container
PORT := 5000
ENV_FILE := web_app/.env

.PHONY: all build run stop clean

all: build run

build:
	docker build -t $(IMAGE_NAME) .

run:
	docker run -d --rm \
		--name $(CONTAINER_NAME) \
		-p $(PORT):$(PORT) \
		-v "$(shell pwd)/$(ENV_FILE):/app/$(ENV_FILE)" \
		$(IMAGE_NAME)
	@echo "Visit http://localhost:5000"

stop:
	-docker stop $(CONTAINER_NAME)

# Remove unused images and volumes.
clean:
	-docker image prune -f
	-docker volume prune -f
