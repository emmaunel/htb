
kali := hilalh/kali-linux:latest

build: ## build the docker image
	@docker build -t $(kali) .

run: build ## run the docker container for hackthebox pentesting
	@docker run -it --privileged $(kali) /bin/bash

## sudo ./tunnel.sh
## once tunnel has enabled, use pw: password
## connect to VPN using openvpn --config <myvpnfile> --daemon

help: ## lists useful commands. other commands may be available, check the Makefile
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help