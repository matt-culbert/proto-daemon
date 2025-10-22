COMPRESSION := $(shell python preprocessor.py)

# Default build rule
http:
	@if "$(COMPRESSION)"=="y" ( \
		go build -trimpath -ldflags "-X main.CompUUID=$(RAND_NUM) -s -w" -tags "withComp withHttp" ./base_config/daemon  \
	) else ( \
		go build -trimpath -ldflags "-X main.CompUUID=$(RAND_NUM) -s -w" -tags "withHttp" ./base_config/daemon \
	)

# DNS build rule
dns:
	@if "$(COMPRESSION)"=="y" ( \
		go build -trimpath -ldflags "-X main.CompUUID=$(RAND_NUM) -s -w" -tags "withComp withDns" ./base_config/daemon  \
	) else ( \
		go build -trimpath -ldflags "-X main.CompUUID=$(RAND_NUM) -s -w" -tags "withDns" ./base_config/daemon \
	)

# Clean rule to remove the binary
clean:
	rm -f daemon.exe