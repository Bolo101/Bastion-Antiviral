# Define variables

SCRIPT_ISO    := forgeIso64.sh

DIR_ISO_64     := iso-64-bits

BUILD_DIR_ISO_64    := ./iso-64-bits/debian-live-build

.PHONY: all kde all-iso clean help

# Default target: run the script

all:
	cd $(DIR_ISO_64) && chmod +x $(SCRIPT_ISO) && bash $(SCRIPT_ISO)

# Build all ISOs

all-iso:
	@echo "Building all ISOs..."
	@$(MAKE) all
	@echo "All ISOs built successfully!"

# Clean target: remove the debian-live-build directory in all folders

clean:
	rm -rf $(BUILD_DIR_ISO_64)

# Help target

help:
	@echo "Available commands:"
	@echo "  make all     - Build ISO (64-bit)"
	@echo "  make clean   - Remove the build directories in all folders"

# Catch-all for invalid commands

.DEFAULT:
	@echo "Invalid command: '$@'"
	@echo ""
	@$(MAKE) help
	@false