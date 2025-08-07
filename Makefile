# ===================================================================
# 🔬 RuneAnalyzer - Advanced Linux Executable Security & Performance Analyzer v1.0.0
# Professional Development & Production Makefile
# 
# Created by Christopher Michko | Co-developed with GitHub Copilot
# Part of the rune* toolkit (runepkg, runarlinux, runeanalyzer)
# ===================================================================

# Compiler and build configuration
CC := gcc
SRCDIR := src
OBJDIR := build
BINDIR := bin
TARGET := runeanalyzer
VERSION := 1.0.0

# Source files
SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Compiler flags for different build types
CFLAGS_BASE := -Wall -Wextra -Wno-unused-parameter -std=c99 -DRUNEANALYZER_VERSION='"$(VERSION)"'
CFLAGS_DEBUG := $(CFLAGS_BASE) -g -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer
CFLAGS_RELEASE := $(CFLAGS_BASE) -O2 -DNDEBUG -march=native -flto
CFLAGS_PROFILE := $(CFLAGS_BASE) -O2 -g -pg -fprofile-arcs -ftest-coverage

# Linker flags
LDFLAGS_BASE := 
LDFLAGS_DEBUG := -fsanitize=address
LDFLAGS_RELEASE := -s -flto
LDFLAGS_PROFILE := -pg -fprofile-arcs -ftest-coverage

# Default build type
BUILD_TYPE ?= release
ifeq ($(BUILD_TYPE),debug)
	CFLAGS := $(CFLAGS_DEBUG)
	LDFLAGS := $(LDFLAGS_DEBUG)
	TARGET_SUFFIX := _debug
else ifeq ($(BUILD_TYPE),profile)
	CFLAGS := $(CFLAGS_PROFILE)
	LDFLAGS := $(LDFLAGS_PROFILE)
	TARGET_SUFFIX := _profile
else
	CFLAGS := $(CFLAGS_RELEASE)
	LDFLAGS := $(LDFLAGS_RELEASE)
	TARGET_SUFFIX :=
endif

# Final target path
TARGET_PATH := $(BINDIR)/$(TARGET)$(TARGET_SUFFIX)

# Installation paths
PREFIX ?= /usr/local
INSTALL_BINDIR := $(PREFIX)/bin
INSTALL_MANDIR := $(PREFIX)/share/man/man1
INSTALL_DOCDIR := $(PREFIX)/share/doc/runeanalyzer

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

.PHONY: all clean clean-all help install uninstall test demo
.DEFAULT_GOAL := all

# Default build target
all: banner $(TARGET_PATH)
	@printf "$(COLOR_GREEN)$(COLOR_BOLD)✅ RuneAnalyzer $(VERSION) built successfully!$(COLOR_RESET)\n"
	@printf "$(COLOR_CYAN)   Executable: $(TARGET_PATH)$(COLOR_RESET)\n"
	@printf "$(COLOR_CYAN)   Build Type: $(BUILD_TYPE)$(COLOR_RESET)\n"
	@printf "$(COLOR_YELLOW)   Try: ./$(TARGET_PATH) --help$(COLOR_RESET)\n"

# Build the main executable
$(TARGET_PATH): $(OBJECTS) | $(BINDIR)
	@printf "$(COLOR_BLUE)🔗 Linking $(TARGET)$(TARGET_SUFFIX)...$(COLOR_RESET)\n"
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@printf "$(COLOR_BLUE)🔨 Compiling $<...$(COLOR_RESET)\n"
	$(CC) $(CFLAGS) -c $< -o $@

# Create directories
$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(BINDIR):
	@mkdir -p $(BINDIR)

# ===================================================================
# 🧹 CLEANING TARGETS
# ===================================================================

# Standard clean - removes build artifacts but keeps directories
clean:
	@printf "$(COLOR_YELLOW)🧹 Cleaning build artifacts...$(COLOR_RESET)\n"
	@rm -f $(OBJDIR)/*.o 2>/dev/null || true
	@rm -f $(OBJDIR)/*.d 2>/dev/null || true
	@rm -f $(BINDIR)/$(TARGET)* 2>/dev/null || true
	@rm -f *.gcno *.gcda *.gcov gmon.out 2>/dev/null || true
	@printf "$(COLOR_GREEN)✅ Clean completed$(COLOR_RESET) (removed: *.o, *.d, executables, coverage files)\n"

# Deep clean - removes all generated files and directories
clean-all: clean
	@printf "$(COLOR_YELLOW)🧹 Deep cleaning all generated files...$(COLOR_RESET)\n"
	@rm -rf $(OBJDIR) $(BINDIR)
	@rm -rf coverage/ profile/
	@rm -f core core.*
	@rm -f .vscode/ipch/
	@find . -name "*.o" -delete 2>/dev/null || true
	@find . -name "*.gcno" -delete 2>/dev/null || true
	@find . -name "*.gcda" -delete 2>/dev/null || true
	@find . -name "*.gcov" -delete 2>/dev/null || true
	@find . -name "*~" -delete 2>/dev/null || true
	@find . -name "*.bak" -delete 2>/dev/null || true
	@printf "$(COLOR_GREEN)✅ Deep clean completed$(COLOR_RESET)\n"

# Distclean - reset to pristine state
distclean: clean-all
	@printf "$(COLOR_YELLOW)🧹 Distribution clean - resetting to pristine state...$(COLOR_RESET)\n"
	@rm -rf autom4te.cache/ config.log config.status
	@rm -f Makefile.bak configure.bak
	@printf "$(COLOR_GREEN)✅ Distribution clean completed$(COLOR_RESET)\n"

# ===================================================================
# 🔧 BUILD VARIANTS
# ===================================================================

# Debug build with sanitizers
debug:
	@$(MAKE) BUILD_TYPE=debug all

# Release build optimized
release:
	@$(MAKE) BUILD_TYPE=release all

# Profile build with coverage
profile:
	@$(MAKE) BUILD_TYPE=profile all

# Static analysis build
static-check: clean
	@printf "$(COLOR_BLUE)🔍 Running static analysis...$(COLOR_RESET)\n"
	@command -v cppcheck >/dev/null && cppcheck --enable=all --std=c99 $(SRCDIR)/ || printf "$(COLOR_YELLOW)⚠️  cppcheck not found, skipping$(COLOR_RESET)\n"
	@$(MAKE) CC=clang CFLAGS="$(CFLAGS_BASE) -Weverything -Wno-padded -Wno-disabled-macro-expansion" all

# ===================================================================
# 📦 INSTALLATION TARGETS
# ===================================================================

install: $(TARGET_PATH)
	@printf "$(COLOR_BLUE)📦 Installing RuneAnalyzer $(VERSION)...$(COLOR_RESET)\n"
	@install -d $(INSTALL_BINDIR)
	@install -m 755 $(TARGET_PATH) $(INSTALL_BINDIR)/$(TARGET)
	@printf "$(COLOR_GREEN)✅ Installed to $(INSTALL_BINDIR)/$(TARGET)$(COLOR_RESET)\n"

uninstall:
	@printf "$(COLOR_YELLOW)🗑️  Uninstalling RuneAnalyzer...$(COLOR_RESET)\n"
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
	@./$(TARGET_PATH) -vv /usr/bin/echo "Deep analysis test" >/dev/null
	@printf "$(COLOR_GREEN)✅ Basic tests passed$(COLOR_RESET)\n"

# Comprehensive test suite
test-full: $(TARGET_PATH)
	@printf "$(COLOR_BLUE)🧪 Running comprehensive test suite...$(COLOR_RESET)\n"
	@printf "$(COLOR_CYAN)Testing basic functionality...$(COLOR_RESET)\n"
	@./$(TARGET_PATH) --version
	@./$(TARGET_PATH) /usr/bin/ls >/dev/null
	@printf "$(COLOR_CYAN)Testing deep analysis mode...$(COLOR_RESET)\n"
	@./$(TARGET_PATH) -vv /usr/bin/sort < /etc/passwd >/dev/null
	@./$(TARGET_PATH) -vv --json /usr/bin/grep "root" /etc/passwd >/dev/null
	@printf "$(COLOR_CYAN)Testing various tool types...$(COLOR_RESET)\n"
	@./$(TARGET_PATH) -vv /usr/bin/head -n 5 /etc/passwd >/dev/null
	@./$(TARGET_PATH) -vv /usr/bin/find /tmp -maxdepth 1 >/dev/null 2>&1
	@printf "$(COLOR_GREEN)✅ Comprehensive tests passed$(COLOR_RESET)\n"

# Memory leak testing
test-memory: debug
	@printf "$(COLOR_BLUE)🔍 Running memory leak tests...$(COLOR_RESET)\n"
	@./$(BINDIR)/$(TARGET)_debug -vv /usr/bin/echo "Memory test"
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
banner:
	@printf "$(COLOR_BOLD)$(COLOR_BLUE)"
	@printf "═══════════════════════════════════════════════════════════════\n"
	@printf "🔬 RuneAnalyzer - Universal Linux Tool Analyzer v$(VERSION)\n"
	@printf "   Building the world's first universal tool intelligence system\n"
	@printf "═══════════════════════════════════════════════════════════════\n"
	@printf "$(COLOR_RESET)"

# Show build information
info:
	@printf "$(COLOR_BOLD)$(COLOR_CYAN)📋 Build Information:$(COLOR_RESET)\n"
	@printf "$(COLOR_YELLOW)Version:$(COLOR_RESET)     $(VERSION)\n"
	@printf "$(COLOR_YELLOW)Compiler:$(COLOR_RESET)    $(CC)\n"
	@printf "$(COLOR_YELLOW)Build Type:$(COLOR_RESET)  $(BUILD_TYPE)\n"
	@printf "$(COLOR_YELLOW)CFLAGS:$(COLOR_RESET)      $(CFLAGS)\n"
	@printf "$(COLOR_YELLOW)LDFLAGS:$(COLOR_RESET)     $(LDFLAGS)\n"
	@printf "$(COLOR_YELLOW)Target:$(COLOR_RESET)      $(TARGET_PATH)\n"
	@printf "$(COLOR_YELLOW)Sources:$(COLOR_RESET)     $(SOURCES)\n"
	@printf "$(COLOR_YELLOW)Objects:$(COLOR_RESET)     $(OBJECTS)\n"

# Help system
help:
	@printf "$(COLOR_BOLD)$(COLOR_BLUE)🔬 RuneAnalyzer $(VERSION) - Universal Linux Tool Analyzer$(COLOR_RESET)\n"
	@printf "$(COLOR_CYAN)Professional Development & Production Makefile$(COLOR_RESET)\n\n"
	@printf "$(COLOR_BOLD)🎯 Main Targets:$(COLOR_RESET)\n"
	@printf "  $(COLOR_GREEN)all$(COLOR_RESET)          Build RuneAnalyzer (default: release)\n"
	@printf "  $(COLOR_GREEN)clean$(COLOR_RESET)        Remove build artifacts\n"
	@printf "  $(COLOR_GREEN)clean-all$(COLOR_RESET)    Deep clean all generated files\n"
	@printf "  $(COLOR_GREEN)distclean$(COLOR_RESET)    Reset to pristine state\n\n"
	@printf "$(COLOR_BOLD)🔧 Build Variants:$(COLOR_RESET)\n"
	@printf "  $(COLOR_GREEN)debug$(COLOR_RESET)        Debug build with sanitizers\n"
	@printf "  $(COLOR_GREEN)release$(COLOR_RESET)      Optimized release build (default)\n"
	@printf "  $(COLOR_GREEN)profile$(COLOR_RESET)      Profiling build with coverage\n"
	@printf "  $(COLOR_GREEN)static-check$(COLOR_RESET) Static analysis build\n\n"
	@printf "$(COLOR_BOLD)📦 Installation:$(COLOR_RESET)\n"
	@printf "  $(COLOR_GREEN)install$(COLOR_RESET)      Install RuneAnalyzer system-wide\n"
	@printf "  $(COLOR_GREEN)uninstall$(COLOR_RESET)    Remove from system\n\n"
	@printf "$(COLOR_BOLD)🧪 Testing & Quality:$(COLOR_RESET)\n"
	@printf "  $(COLOR_GREEN)test$(COLOR_RESET)         Quick functionality tests\n"
	@printf "  $(COLOR_GREEN)test-full$(COLOR_RESET)    Comprehensive test suite\n"
	@printf "  $(COLOR_GREEN)test-memory$(COLOR_RESET)  Memory leak testing\n"
	@printf "  $(COLOR_GREEN)benchmark$(COLOR_RESET)    Performance benchmarking\n\n"
	@printf "$(COLOR_BOLD)🎮 Development:$(COLOR_RESET)\n"
	@printf "  $(COLOR_GREEN)demo$(COLOR_RESET)         Interactive demonstration\n"
	@printf "  $(COLOR_GREEN)dev$(COLOR_RESET)          Quick development cycle\n"
	@printf "  $(COLOR_GREEN)format$(COLOR_RESET)       Code formatting (clang-format)\n"
	@printf "  $(COLOR_GREEN)info$(COLOR_RESET)         Show build information\n\n"
	@printf "$(COLOR_BOLD)💡 Examples:$(COLOR_RESET)\n"
	@printf "  $(COLOR_YELLOW)make$(COLOR_RESET)                    # Build release version\n"
	@printf "  $(COLOR_YELLOW)make debug$(COLOR_RESET)              # Build debug version\n"
	@printf "  $(COLOR_YELLOW)make clean && make$(COLOR_RESET)      # Clean and rebuild\n"
	@printf "  $(COLOR_YELLOW)make dev$(COLOR_RESET)                # Development cycle\n"
	@printf "  $(COLOR_YELLOW)make test-full$(COLOR_RESET)          # Run all tests\n"
	@printf "  $(COLOR_YELLOW)make demo$(COLOR_RESET)               # See RuneAnalyzer in action\n\n"

# ===================================================================
# 📋 DEPENDENCIES
# ===================================================================

# Automatic dependency generation
-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.d: $(SRCDIR)/%.c | $(OBJDIR)
	@$(CC) $(CFLAGS_BASE) -MM -MT '$(@:.d=.o)' $< > $@

# ===================================================================
# 🔚 END OF MAKEFILE
# ===================================================================
