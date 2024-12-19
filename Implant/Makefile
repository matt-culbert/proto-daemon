# Generate a random UUID-like number (e.g., a random integer between 1000 and 9999)
RAND_NUM := $(shell powershell -Command "[System.Random]::new().Next(1000,9999)")
BUILD_TAG := $(shell python compress_conf.py)

# Default build rule
build:
	@echo "Building default options with random ID: $(RAND_NUM)"
	@echo "Building with compression: $(BUILD_TAG)"
	@if "$(BUILD_TAG)"=="withComp" ( \
		go build -trimpath -ldflags "-X main.CompUUID=$(RAND_NUM) -s -w" -tags "withComp withHttp" ./preprocessor/daemon  \
	) else ( \
		go build -trimpath -ldflags "-X main.CompUUID=$(RAND_NUM) -s -w" -tags "withHttp" ./preprocessor/daemon \
	)

# Clean rule to remove the binary
clean:
	rm -f daemon.exe