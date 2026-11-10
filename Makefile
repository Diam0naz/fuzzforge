.PHONY: help build test fmt clippy check dev up down logs sandbox-build sample-bundle clean

help:
	@echo "build         cargo build --workspace"
	@echo "test          cargo test --workspace"
	@echo "fmt           cargo fmt --all"
	@echo "clippy        cargo clippy --workspace --all-targets -- -D warnings"
	@echo "sandbox-build build the pinned Trident sandbox image (local tag)"
	@echo "sample-bundle create examples/sample-bundle.tar.gz for intake testing"
	@echo "up            docker compose up --build"
	@echo "down          docker compose down"
	@echo "logs          docker compose logs -f api worker"

build:
	cargo build --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

check:
	cargo check --workspace --all-targets

sandbox-build:
	docker build \
		-t fuzzforge/sandbox:latest \
		--build-arg TRIDENT_VERSION=$${TRIDENT_VERSION:-0.12.0} \
		sandbox

sample-bundle:
	bash examples/scripts/make-sample-bundle.sh

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f api worker

clean:
	cargo clean
	rm -rf frontend/.next frontend/node_modules
