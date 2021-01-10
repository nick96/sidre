IMAGE_NAME=ghcr.io/nick96/sidre/test-service-provider
# B64_IDP_X509=${B64_IDP_X509}
# SP_ENTITY_ID=${SP_ENTITY_ID}
# IDP_ENTITY_ID=${IDP_ENTITY_ID}
GIT_SHA=$(shell git log --oneline -n1 --format=%h)

build:
	docker build -t $(IMAGE_NAME) .

run: build
	docker run \
		--publish 5000:5000 \
		--env B64_IDP_X509=$(B64_IDP_X509) \
		--env SP_ENTITY_ID=$(SP_ENTITY_ID) \
		--env IDP_ENTITY_ID=$(IDP_ENTITY_ID) \
		--interactive \
		--tty \
		$(IMAGE_NAME)


publish: build
	docker tag $(IMAGE_NAME) $(GIT_SHA)
	docker push $(IMAGE_NAME):$(GIT_SHA)
	docker push $(IMAGE_NAME):latest