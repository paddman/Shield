SHELL := /bin/bash
VERSION ?= 0.1.0
GO ?= go
DIST := dist
CMD := ./cmd/ntshield-agent
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all fmt test vet build build-amd64 build-386 package clean

all: test build-amd64

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

build: build-amd64

build-amd64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
		$(GO) build -trimpath -ldflags '$(LDFLAGS)' \
		-o $(DIST)/ntshield-agent-centos6-amd64 $(CMD)

build-386:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 GO386=softfloat \
		$(GO) build -trimpath -ldflags '$(LDFLAGS)' \
		-o $(DIST)/ntshield-agent-centos6-386 $(CMD)

package: test vet build-amd64 build-386
	rm -rf $(DIST)/package-amd64 $(DIST)/package-386
	mkdir -p $(DIST)/package-amd64 $(DIST)/package-386
	cp $(DIST)/ntshield-agent-centos6-amd64 $(DIST)/package-amd64/ntshield-agent
	cp $(DIST)/ntshield-agent-centos6-386 $(DIST)/package-386/ntshield-agent
	for d in $(DIST)/package-amd64 $(DIST)/package-386; do \
		cp scripts/install-centos6.sh $$d/install-centos6.sh; \
		cp scripts/uninstall-centos6.sh $$d/uninstall-centos6.sh; \
		cp packaging/sysv/ntshield-agent $$d/ntshield-agent.init; \
		cp packaging/logrotate/ntshield-agent $$d/ntshield-agent.logrotate; \
		cp config.example.json README.md $$d/; \
		chmod +x $$d/ntshield-agent $$d/install-centos6.sh $$d/uninstall-centos6.sh $$d/ntshield-agent.init; \
	done
	tar -C $(DIST)/package-amd64 -czf $(DIST)/NTShield-CentOS6-Agent-$(VERSION)-amd64.tar.gz .
	tar -C $(DIST)/package-386 -czf $(DIST)/NTShield-CentOS6-Agent-$(VERSION)-386.tar.gz .
	sha256sum $(DIST)/NTShield-CentOS6-Agent-$(VERSION)-*.tar.gz > $(DIST)/SHA256SUMS

clean:
	rm -rf $(DIST)
