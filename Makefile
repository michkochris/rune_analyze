# ===================================================================
# 🔬 rune_analyze - Universal Linux Executable Analysis Framework v1.0.0
# Simplified Development Makefile - Framework Foundation
# 
# Created by Christopher Michko | Co-developed with GitHub Copilot
# Part of the rune* toolkit (runepkg, runarlinux, rune_analyze)
# ===================================================================

# Compiler and build configuration
CC := gcc
SRCDIR := src
TARGET := rune_analyze
VERSION := 1.0.0

# Source files (exclude legacy files)
SOURCES := src/main.c src/rune_framework.c src/rune_config.c src/rune_logging.c src/rune_checkpoint.c src/rune_analysis.c src/rune_output.c

# Compiler flags for different build types
CFLAGS_BASE := -Wall -Wextra -Wno-unused-parameter -std=c99 -DRUNE_ANALYZE_VERSION='"$(VERSION)"'
CFLAGS_DEBUG := $(CFLAGS_BASE) -g -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer
CFLAGS_RELEASE := $(CFLAGS_BASE) -O2 -DNDEBUG -march=native

# Linker flags
LDFLAGS_DEBUG := -fsanitize=address
LDFLAGS_RELEASE := -s

# Default build type
BUILD_TYPE ?= release
ifeq ($(BUILD_TYPE),debug)
	CFLAGS := $(CFLAGS_DEBUG)
	LDFLAGS := $(LDFLAGS_DEBUG)
	TARGET_SUFFIX := _debug
else
	CFLAGS := $(CFLAGS_RELEASE)
	LDFLAGS := $(LDFLAGS_RELEASE)
	TARGET_SUFFIX :=
endif

# Final target (builds directly in root directory)
TARGET_PATH := $(TARGET)$(TARGET_SUFFIX)

# Installation paths
PREFIX ?= /usr/local
INSTALL_BINDIR := $(PREFIX)/bin

# Colors for output
COLOR_RESET := \033[0m
COLOR_BOLD := \033[1m
COLOR_GREEN := \033[32m
COLOR_BLUE := \033[34m
COLOR_YELLOW := \033[33m
COLOR_RED := \033[31m
COLOR_CYAN := \033[36m

# ===================================================================
# 🎯 MAIN TARGETS
# ===================================================================

.PHONY: all clean help install uninstall test debug release
.DEFAULT_GOAL := all

# Default build target - simplified direct compilation
all: banner $(TARGET_PATH)
	@printf "$(COLOR_GREEN)$(COLOR_BOLD)✅ rune_analyze $(VERSION) built successfully!$(COLOR_RESET)\n"
	@printf "$(COLOR_CYAN)   Executable: $(TARGET_PATH)$(COLOR_RESET)\n"
	@printf "$(COLOR_CYAN)   Build Type: $(BUILD_TYPE)$(COLOR_RESET)\n"
	@printf "$(COLOR_YELLOW)   Try: ./$(TARGET_PATH) --help$(COLOR_RESET)\n"

# Build the main executable directly from source files
$(TARGET_PATH): $(SOURCES)
	@printf "$(COLOR_BLUE)🔨 Compiling rune_analyze from sources...$(COLOR_RESET)\n"
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS)

# ===================================================================
# 🧹 CLEANING TARGETS
# ===================================================================

# Clean - remove executables and build artifacts
clean:
	@printf "$(COLOR_YELLOW)🧹 Cleaning build artifacts...$(COLOR_RESET)\n"
	@rm -f $(TARGET) $(TARGET)_debug
	@rm -f *.gcno *.gcda *.gcov gmon.out 2>/dev/null || true
	@rm -f core core.*
	@find . -name "*~" -delete 2>/dev/null || true
	@find . -name "*.bak" -delete 2>/dev/null || true
	@printf "$(COLOR_GREEN)✅ Clean completed$(COLOR_RESET)\n"

# ===================================================================
# 🔧 BUILD VARIANTS
# ===================================================================

# Debug build with sanitizers
debug:
	@$(MAKE) BUILD_TYPE=debug all

# Release build optimized
release:
	@$(MAKE) BUILD_TYPE=release all

# ===================================================================
# 📦 INSTALLATION TARGETS
# ===================================================================

install: $(TARGET_PATH)
	@printf "$(COLOR_BLUE)📦 Installing rune_analyze $(VERSION)...$(COLOR_RESET)\n"
	@install -d $(INSTALL_BINDIR)
	@install -m 755 $(TARGET_PATH) $(INSTALL_BINDIR)/$(TARGET)
	@printf "$(COLOR_GREEN)✅ Installed to $(INSTALL_BINDIR)/$(TARGET)$(COLOR_RESET)\n"

uninstall:
	@printf "$(COLOR_YELLOW)🗑️  Uninstalling rune_analyze...$(COLOR_RESET)\n"
	@rm -f $(INSTALL_BINDIR)/$(TARGET)
	@printf "$(COLOR_GREEN)✅ Uninstalled$(COLOR_RESET)\n"

# ===================================================================
# 🧪 TESTING & VALIDATION
# ===================================================================

# Quick functionality test
test: $(TARGET_PATH)
	@printf "$(COLOR_BLUE)🧪 Running quick tests...$(COLOR_RESET)\n"
	@./$(TARGET_PATH) --version
	@./$(TARGET_PATH) --help >/dev/null
	@./$(TARGET_PATH) /usr/bin/echo "Test successful" >/dev/null
	@printf "$(COLOR_GREEN)✅ Basic tests passed$(COLOR_RESET)\n"

# ===================================================================
# 🎨 BANNER & HELP
# ===================================================================

banner:
	@printf "$(COLOR_CYAN)$(COLOR_BOLD)"
	@printf "═══════════════════════════════════════════════════════════════\n"
	@printf "🔬 rune_analyze - Universal Analysis Framework v$(VERSION)\n"
	@printf "   Framework Foundation for Expert Developer Handoff\n"
	@printf "═══════════════════════════════════════════════════════════════\n"
	@printf "$(COLOR_RESET)"

help:
	@printf "$(COLOR_CYAN)$(COLOR_BOLD)🔬 rune_analyze $(VERSION) - Build System$(COLOR_RESET)\n\n"
	@printf "$(COLOR_BOLD)Available Targets:$(COLOR_RESET)\n"
	@printf "  $(COLOR_GREEN)all$(COLOR_RESET)         Build rune_analyze (default)\n"
	@printf "  $(COLOR_GREEN)debug$(COLOR_RESET)       Build debug version with sanitizers\n"
	@printf "  $(COLOR_GREEN)release$(COLOR_RESET)     Build optimized release version\n"
	@printf "  $(COLOR_GREEN)clean$(COLOR_RESET)       Remove build artifacts\n"
	@printf "  $(COLOR_GREEN)install$(COLOR_RESET)     Install to $(PREFIX)/bin\n"
	@printf "  $(COLOR_GREEN)uninstall$(COLOR_RESET)   Remove from system\n"
	@printf "  $(COLOR_GREEN)test$(COLOR_RESET)        Run quick functionality tests\n"
	@printf "  $(COLOR_GREEN)help$(COLOR_RESET)        Show this help message\n\n"
	@printf "$(COLOR_BOLD)Build Examples:$(COLOR_RESET)\n"
	@printf "  $(COLOR_YELLOW)make$(COLOR_RESET)                    # Build release version\n"
	@printf "  $(COLOR_YELLOW)make debug$(COLOR_RESET)              # Build debug version\n"
	@printf "  $(COLOR_YELLOW)make clean && make$(COLOR_RESET)      # Clean rebuild\n"
	@printf "  $(COLOR_YELLOW)make test$(COLOR_RESET)               # Test functionality\n\n"
	@printf "$(COLOR_BOLD)Framework Structure:$(COLOR_RESET)\n"
	@printf "  $(COLOR_CYAN)src/$(COLOR_RESET)         All .c and .h source files\n"
	@printf "  $(COLOR_CYAN)./rune_analyze$(COLOR_RESET) Compiled executable\n\n"
	@printf "$(COLOR_GREEN)✅ Memory tests completed (check for sanitizer output)$(COLOR_RESET)\n"

# Performance benchmarking
benchmark: $(TARGET_PATH)
	@printf "$(COLOR_BLUE)📊 Running performance benchmarks...$(COLOR_RESET)\n"
	@printf "$(COLOR_CYAN)Benchmarking various tool types:$(COLOR_RESET)\n"
	@printf "$(COLOR_YELLOW)Sort performance:$(COLOR_RESET)\n"
	@seq 1 1000 | ./$(TARGET_PATH) -vv /usr/bin/sort -n >/dev/null
	@printf "$(COLOR_YELLOW)Find performance:$(COLOR_RESET)\n"
	@./$(TARGET_PATH) -vv /usr/bin/find /tmp -name "*.tmp" >/dev/null 2>&1
	@printf "$(COLOR_GREEN)✅ Benchmarks completed$(COLOR_RESET)\n"

# ===================================================================
# 🎮 DEMO & DEVELOPMENT
# ===================================================================

# Interactive demo
demo: $(TARGET_PATH)
	@printf "$(COLOR_BOLD)$(COLOR_BLUE)🎮 RuneAnalyzer $(VERSION) Interactive Demo$(COLOR_RESET)\n"
	@printf "$(COLOR_CYAN)================================$(COLOR_RESET)\n"
	@printf "$(COLOR_YELLOW)1. Basic Analysis:$(COLOR_RESET)\n"
	@./$(TARGET_PATH) /usr/bin/echo "Hello RuneAnalyzer Demo!"
	@printf "\n$(COLOR_YELLOW)2. Deep Analysis Mode (-vv):$(COLOR_RESET)\n"
	@./$(TARGET_PATH) -vv /usr/bin/sort < /etc/passwd
	@printf "\n$(COLOR_YELLOW)3. JSON Output:$(COLOR_RESET)\n"
	@./$(TARGET_PATH) -vv --json /usr/bin/head -n 3 /etc/passwd

# Quick development cycle
dev: clean debug test
	@printf "$(COLOR_GREEN)$(COLOR_BOLD)🚀 Development cycle completed!$(COLOR_RESET)\n"

# Code formatting (if clang-format available)
format:
	@printf "$(COLOR_BLUE)🎨 Formatting code...$(COLOR_RESET)\n"
	@command -v clang-format >/dev/null && find $(SRCDIR) -name "*.c" -o -name "*.h" | xargs clang-format -i || printf "$(COLOR_YELLOW)⚠️  clang-format not found, skipping$(COLOR_RESET)\n"
	@printf "$(COLOR_GREEN)✅ Code formatting completed$(COLOR_RESET)\n"

# ===================================================================
# ℹ️ INFORMATION TARGETS
# ===================================================================

# Project banner
# ===================================================================
# � END OF MAKEFILE - Framework Foundation Complete
# ===================================================================
