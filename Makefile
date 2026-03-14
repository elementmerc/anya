# ── Anya Makefile ─────────────────────────────────────────────────────────────
# Usage:
#   make build          — cargo build (debug)
#   make release        — cargo build --release
#   make test           — cargo test
#   make clippy         — cargo clippy
#   make fmt            — cargo fmt
#   make docker-build   — build the Docker image
#   make docker-test    — smoke-test the image
#   make docker-push    — tag and push to Docker Hub (requires DOCKER_HUB_USER)
#
# Required env vars for docker-push:
#   DOCKER_HUB_USER     — your Docker Hub username
#   VERSION             — image version tag (defaults to crate version)

CRATE_NAME      := anya-security-core
IMAGE_NAME      := anya
VERSION         ?= $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
DOCKER_HUB_USER ?= ""

.PHONY: build release test clippy fmt \
        docker-build docker-test docker-push docker-local \
        release-dry tag-release \
        clean

# ── Rust targets ──────────────────────────────────────────────────────────────

build:
	cargo build -p $(CRATE_NAME)

release:
	cargo build --release -p $(CRATE_NAME)

test:
	cargo test -p $(CRATE_NAME)

clippy:
	cargo clippy -p $(CRATE_NAME) -- -D warnings

fmt:
	cargo fmt --all

clean:
	cargo clean

# ── Docker targets ────────────────────────────────────────────────────────────

docker-build:
	docker build -t $(IMAGE_NAME):latest .
	@echo ""
	@echo "Image size:"
	@docker image inspect $(IMAGE_NAME):latest --format='{{.Size}}' | \
		awk '{printf "  %.1f MB\n", $$1/1024/1024}'

docker-test:
	@echo "--- smoke test: --version ---"
	docker run --rm $(IMAGE_NAME):latest --version
	@echo ""
	@echo "--- smoke test: --help ---"
	docker run --rm $(IMAGE_NAME):latest --help
	@echo ""
	@echo "All Docker smoke tests passed."

docker-push:
	@if [ -z "$(DOCKER_HUB_USER)" ]; then \
		echo "Error: DOCKER_HUB_USER is not set."; \
		echo "Usage: make docker-push DOCKER_HUB_USER=myusername"; \
		exit 1; \
	fi
	docker tag $(IMAGE_NAME):latest $(DOCKER_HUB_USER)/$(IMAGE_NAME):latest
	docker tag $(IMAGE_NAME):latest $(DOCKER_HUB_USER)/$(IMAGE_NAME):$(VERSION)
	docker push $(DOCKER_HUB_USER)/$(IMAGE_NAME):latest
	docker push $(DOCKER_HUB_USER)/$(IMAGE_NAME):$(VERSION)
	@echo ""
	@echo "Pushed $(DOCKER_HUB_USER)/$(IMAGE_NAME):latest"
	@echo "Pushed $(DOCKER_HUB_USER)/$(IMAGE_NAME):$(VERSION)"

# Build and run the Docker image locally (no push required)
docker-local:
	docker build -t $(IMAGE_NAME):local .
	@echo ""
	@echo "Image built as $(IMAGE_NAME):local"
	@echo "Run: docker run --rm -v \$$(pwd):/samples $(IMAGE_NAME):local /samples/file.exe"

# ── Release helpers ───────────────────────────────────────────────────────────

# Dry-run: build release binary and print version, but do NOT tag or push
release-dry:
	@echo "--- cargo build --release ---"
	cargo build --release -p $(CRATE_NAME)
	@echo ""
	@echo "--- version ---"
	./target/release/anya --version
	@echo ""
	@echo "Dry run complete. No tag was created."

# Create and push an annotated git tag to trigger the release workflow
# Usage: make tag-release VERSION=0.4.0
tag-release:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required."; \
		echo "Usage: make tag-release VERSION=0.4.0"; \
		exit 1; \
	fi
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "Error: tag v$(VERSION) already exists."; \
		exit 1; \
	fi
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"
	@echo ""
	@echo "Tag v$(VERSION) pushed — release workflow triggered."
