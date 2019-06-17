CONTAINER_IMAGE_NAME := test

setup-container-structure-test:
	scripts/setup-container-structure-test.sh

build-docker-image:
	docker build -t "$(CONTAINER_IMAGE_NAME)" .

test-docker-image:
	container-structure-test test --image "$(CONTAINER_IMAGE_NAME)" --config ./test_config.yaml
