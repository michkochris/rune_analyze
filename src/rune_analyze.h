/**
 * rune_analyze.h - Main header for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * Universal Linux Executable Analysis Framework
 * Framework foundation for expert developer handoff
 *
 * This program is free software under GPL v3 License.
 */

#ifndef RUNE_ANALYZE_H
#define RUNE_ANALYZE_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <ctype.h>

// Version and framework info
#define RUNE_ANALYZE_VERSION "1.0.0"
#define MAX_OUTPUT_SIZE 65536
#define MAX_COMMAND_LENGTH 4096
#define MAX_ARGS 256
#define MAX_CHECKPOINTS 1024

// Forward declarations for modular components
typedef struct rune_config rune_config_t;
typedef struct rune_results rune_results_t;
typedef struct rune_checkpoint rune_checkpoint_t;

// Include modular headers
#include "rune_types.h"
#include "rune_config.h"
#include "rune_logging.h"
#include "rune_checkpoint.h"
#include "rune_analysis.h"
#include "rune_security.h"
#include "rune_performance.h"
#include "rune_output.h"

// Main framework functions
int rune_initialize(int argc, char **argv);
int rune_execute_analysis(void);
void rune_cleanup(void);
void rune_print_usage(const char* program_name);

#endif /* RUNE_ANALYZE_H */
