
kali := hilalh/kali-linux:latest
pw := $(HTB_PASSWORD)

build: ## build the docker image
	@echo $(pw)
	@docker build -t $(kali) . --build-arg PASSWORD=$(pw)

run: build ## run the docker container for hackthebox pentesting
	@docker run -it --privileged $(kali) /bin/bash

help: ## lists useful commands. other commands may bexxxxx available, check the Makefile
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help