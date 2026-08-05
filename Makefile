.PHONY: build run test docker

build:
	go build -o bin/server ./cmd/server
	go build -o bin/client ./cmd/client

run:
	docker compose up -d

test:
	go test ./... -v
	go test -race ./... -v

docker:
	docker build -t ot-banner/server .
	docker compose up -d --build
