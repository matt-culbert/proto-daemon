# Generate a random UUID-like number (e.g., a random integer between 1000 and 9999)
RAND_NUM := $(shell powershell -Command "[System.Random]::new().Next(1000,9999)")
BUILD_TAG := $(shell python compress_conf.py)

# Default build rule
build:
	@echo "Building default options with random ID: $(RAND_NUM)"
	@echo "Building with compression: $(BUILD_TAG)"
	@if "$(BUILD_TAG)"=="withComp" ( \
		go build  -trimpath -ldflags "-X main.CompUUID=$(RAND_NUM) -s -w" -tags "withComp withHttp" ./daemon \
	) else ( \
		go build  -trimpath -ldflags "-X main.CompUUID=$(RAND_NUM) -s -w" -tags "withHttp" ./daemon \
	)



# Enable Lua support
withLua:
	@echo "Building with random ID: $(RAND_NUM) and with Lua support enabled"
	go build -ldflags "-X main.CompUUID=$(RAND_NUM)" -tags "withLua withHttp" ./daemon

# Without compression
noComp:
	@echo "Building with random ID: $(RAND_NUM) and no data compression"
	@echo "Running python script"
	python non_comp.py
	go build -ldflags " -X main.CompUUID=$(RAND_NUM)" -tags "withHttp" ./daemon

# With compression
# Compresses the config file embedded and compresses data sent to the C2
withComp:
	@echo "Building with random ID: $(RAND_NUM) and with data compression"
	@echo "Running python script"
	python compress_conf.py
	go build -ldflags " -X main.CompUUID=$(RAND_NUM)" -tags "withComp withHttp" ./daemon
# Clean rule to remove the binary
clean:
	rm -f daemon.exe