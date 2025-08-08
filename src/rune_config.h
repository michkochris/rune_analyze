/**
 * rune_config.h - Configuration management for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 */

#ifndef RUNE_CONFIG_H
#define RUNE_CONFIG_H

#include "rune_types.h"

// Configuration management
extern rune_config_t g_config;
extern rune_results_t g_results;

// Configuration functions
int rune_config_init(void);
int rune_config_parse_args(int argc, char **argv);
void rune_config_cleanup(void);
int rune_config_validate(void);

// Configuration accessors
const char* rune_get_target_executable(void);
char** rune_get_target_args(void);
int rune_get_target_argc(void);
int rune_is_verbose_mode(void);
int rune_is_deep_analysis_enabled(void);
int rune_get_output_format(void);

// Safe string operations - Defensive C Programming
#define RUNE_SAFE_STRNCPY(dest, src, size) do { \
    strncpy(dest, src, size - 1); \
    (dest)[size - 1] = '\0'; \
} while(0)

#define RUNE_SAFE_STRNCAT(dest, src, size) do { \
    size_t current_len = strnlen(dest, size - 1); \
    size_t remaining = size - current_len - 1; \
    if (remaining > 0) { \
        strncat(dest, src, remaining); \
        (dest)[size - 1] = '\0'; \
    } \
} while(0)

// Input validation macros
#define RUNE_VALIDATE_POINTER(ptr, name) do { \
    if (!(ptr)) { \
        rune_log(0, "Error: NULL pointer in %s\n", name); \
        return -1; \
    } \
} while(0)

#define RUNE_VALIDATE_RANGE(value, min, max, name) do { \
    if ((value) < (min) || (value) > (max)) { \
        rune_log(0, "Error: %s value %d out of range [%d, %d]\n", name, value, min, max); \
        (value) = ((value) < (min)) ? (min) : (max); \
    } \
} while(0)

#endif /* RUNE_CONFIG_H */
