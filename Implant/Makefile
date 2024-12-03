# Generate a random UUID-like number (e.g., a random integer between 1000 and 9999)
RAND_NUM := $(shell powershell -Command "[System.Random]::new().Next(1000,9999)")
# Extract abs_path from s_conf.json using jq
GET_ABS_PATH := $(shell jq -r '.listeners[] | select(.name=="DefGET") | .abs_path' ..\\Server\\s_conf.json)
PST_ABS_PATH := $(shell jq -r '.listeners[] | select(.name=="DefPOST") | .abs_path' ..\\Server\\s_conf.json)

# Default build rule
# Requires defining the comm method by passing an argument
build:
	@echo "Building default options with random ID: $(RAND_NUM)"
	go build -ldflags "-X main.CompUUID=$(RAND_NUM) -X main.GetURI=$(GET_ABS_PATH) -X main.PostURI=$(PST_ABS_PATH)" -tags "$(METHOD)" ./daemon

# Enable Lua support
# Requires defining the comm method by passing an argument
withLua:
	@echo "Building with random ID: $(RAND_NUM) and with Lua support enabled"
	go build -ldflags "-X main.CompUUID=$(RAND_NUM) -X main.GetURI=$(GET_ABS_PATH) -X main.PostURI=$(PST_ABS_PATH)" -tags "$(METHOD) withLua" ./daemon

# Clean rule to remove the binary
clean:
	rm -f daemon.exe