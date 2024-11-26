# Output binary name
OUTPUT := program

# Package to build
PACKAGE := ./http

# Build tags
PROTO := http

# Generate a random UUID-like number (e.g., a random integer between 1000 and 9999)
RAND_NUM := $(shell shuf -i 1000-9999 -n 1)

# Default build rule
build:
	@echo "Building with random CompUUID=$(RAND_NUM)"
	go build -ldflags "-X main.CompUUID=$(RAND_NUM)" -tags "$(PROTO)" -o $(OUTPUT) $(PACKAGE)

# Enable a subset of features (example: only featureA and featureB)
build_WithLua:
	go build -ldflags "-X main.CompUUID=$(RAND_NUM)" -tags "$(PROTO) lua" -o $(OUTPUT) $(PACKAGE)

# Clean rule to remove the binary
clean:
	rm -f $(OUTPUT)
