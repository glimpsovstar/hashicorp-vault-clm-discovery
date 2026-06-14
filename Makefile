.PHONY: build test lint run migrate-up docker-up docker-down

build:
	go build -o bin/clm-discovery ./cmd/clm-discovery
	go build -o bin/clm-scan ./cmd/clm-scan

test:
	go test ./...

lint:
	golangci-lint run ./...

run:
	DATABASE_URL=postgres://clm:clm@localhost:5432/clm?sslmode=disable go run ./cmd/clm-discovery

migrate-up:
	migrate -path migrations -database "$${DATABASE_URL}" up

docker-up:
	docker compose -f deploy/docker-compose.yml up --build -d

docker-down:
	docker compose -f deploy/docker-compose.yml down
