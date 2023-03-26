NAME=dns-bash
VERSION=1.0.0

help: ## Get help for Makefile
	@echo "\n#### $(NAME) v$(VERSION) ####\n"
	@echo "Available targets:\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo "\n"

install: ## Install requirements locally
	sudo apt-get install -y dnsutils bash curl jq apt-utils

test: ## Run tests
	@echo "No tests yet"
	
run: ## Run dns-bash locally
	chmod +x dns-bash.sh && bash dns-bash.sh

.PHONY: help run install