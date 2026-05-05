# Define variables

SCRIPT_XFCE     := forgeIsoXfce.sh

DIR_XFCE_64     := xfce-64-bits

BUILD_DIR_XFCE_64    := ./xfce-64-bits/debian-live-build

.PHONY: all kde all-iso clean help

# Default target: run the script

all:
	cd $(DIR_XFCE_64) && chmod +x $(SCRIPT_XFCE) && bash $(SCRIPT_XFCE)

# Build all ISOs

all-iso:
	@echo "Building all ISOs..."
	@$(MAKE) all
	@echo "All ISOs built successfully!"

# Clean target: remove the debian-live-build directory in all folders

clean:
	rm -rf $(BUILD_DIR_XFCE_64)

# Help target

help:
	@echo "Available commands:"
	@echo "  make all     - Build XFCE ISO (64-bit)"
	@echo "  make clean   - Remove the build directories in all folders"

# Catch-all for invalid commands

.DEFAULT:
	@echo "Invalid command: '$@'"
	@echo ""
	@$(MAKE) help
	@false