NAME=dns-bash
VERSION=1.0.0

help: ## Get help for Makefile
	@echo "\n#### $(NAME) v$(VERSION) ####\n"
	@echo "Available targets:\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo "\n"

install: ## Install requirements locally
	sudo apt-get install -y dnsutils bash curl jq apt-utils

run: ## Run dns-bash locally
	chmod +x dns-bash.sh && bash dns-bash.sh
	
docker-build: ## Build docker image
	docker build --no-cache -t $(NAME) .

docker-run: ## Run discord bot inside docker container
	docker run --privileged --network=host --env-file .env --name dns-bash $(NAME)

docker-sh: ## Shell into docker container
	docker run --network=host --privileged -it $(NAME) sh

docker-remove: ## Remove docker container
	docker container rm $(NAME)

.PHONY: help docker-build docker-run docker-sh docker-remove run install