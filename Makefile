GO ?= go
PNPM ?= pnpm

.PHONY: build test test-race vet config-check benchmark-config-check alert-check run-lab run-e2e run-service-e2e web-dev web-build web-verify verify release clean

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/sgw-c ./cmd/sgw-c
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/sgw-u ./cmd/sgw-u
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/pgw-c ./cmd/pgw-c
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/pgw-u ./cmd/pgw-u
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/sgw-e2e ./cmd/sgw-e2e
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/cups-service-e2e ./cmd/cups-service-e2e
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/sgw-lab ./cmd/sgw-lab
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/kernel-gtp-lab ./cmd/kernel-gtp-lab
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/cups-dataplane-bench ./cmd/cups-dataplane-bench
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/sgwu-ebpf-bench ./cmd/sgwu-ebpf-bench
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/sgwu-wire-bench ./cmd/sgwu-wire-bench
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o bin/cups-control-bench ./cmd/cups-control-bench

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

config-check:
	$(GO) run ./cmd/sgw-c --config configs/sgw-c.lab.yaml --check-config
	$(GO) run ./cmd/sgw-u --config configs/sgw-u.lab.yaml --check-config
	$(GO) run ./cmd/pgw-c --config configs/pgw-c.lab.yaml --check-config
	$(GO) run ./cmd/pgw-u --config configs/pgw-u.lab.yaml --check-config

benchmark-config-check:
	$(GO) run ./cmd/sgw-c --config deploy/benchmark/sgw-c.vps-netns.yaml --check-config
	$(GO) run ./cmd/sgw-u --config deploy/benchmark/sgw-u.vps-netns.yaml --check-config
	$(GO) run ./cmd/sgw-u --config deploy/benchmark/sgw-u.tcx-smoke.yaml --check-config

alert-check:
	$(GO) run ./cmd/lodestar-alert-check --rules deploy/prometheus/lodestar-cups-alerts.yaml

run-lab:
	$(GO) run ./cmd/sgw-lab

run-e2e:
	$(GO) run ./cmd/sgw-e2e

run-service-e2e:
	$(GO) run ./cmd/cups-service-e2e

web-dev:
	cd web && $(PNPM) dev

web-build:
	cd web && $(PNPM) build

web-verify:
	cd web && $(PNPM) typecheck
	cd web && $(PNPM) lint
	cd web && $(PNPM) build

verify: vet test test-race config-check benchmark-config-check alert-check build web-verify

release:
	deploy/release/qualify-source.sh $(RELEASE_VERSION)

clean:
	rm -rf bin coverage web/dist web/.next
