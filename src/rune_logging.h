/**
 * rune_logging.h - Logging system for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 */

#ifndef RUNE_LOGGING_H
#define RUNE_LOGGING_H

// Log levels
#define RUNE_LOG_ERROR   0
#define RUNE_LOG_WARNING 1
#define RUNE_LOG_INFO    2
#define RUNE_LOG_DEBUG   3

// Main logging function
void rune_log(int level, const char* format, ...);

// Convenience macros
#define rune_log_error(...)   rune_log(RUNE_LOG_ERROR, __VA_ARGS__)
#define rune_log_warning(...) rune_log(RUNE_LOG_WARNING, __VA_ARGS__)
#define rune_log_info(...)    rune_log(RUNE_LOG_INFO, __VA_ARGS__)
#define rune_log_debug(...)   rune_log(RUNE_LOG_DEBUG, __VA_ARGS__)

// Safe memory operations
void* rune_safe_malloc(size_t size);
char* rune_safe_strdup(const char* src, size_t max_len);
int rune_safe_atoi(const char* str, int* result);

#endif /* RUNE_LOGGING_H */
