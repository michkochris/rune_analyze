/**
 * rune_logging.c - Logging system implementation
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 */

#include "rune_analyze.h"

// Main logging function
void rune_log(int level, const char* format, ...) {
    // Only print if verbose enough
    if (level > rune_is_verbose_mode()) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    
    // Add level prefixes
    switch (level) {
        case RUNE_LOG_ERROR:
            fprintf(stderr, "[ERROR] ");
            break;
        case RUNE_LOG_WARNING:
            fprintf(stderr, "[WARNING] ");
            break;
        case RUNE_LOG_INFO:
            if (rune_is_verbose_mode() >= 2) {
                printf("[INFO] ");
            }
            break;
        case RUNE_LOG_DEBUG:
            if (rune_is_verbose_mode() >= 3) {
                printf("[DEBUG] ");
            }
            break;
    }
    
    // Print the actual message
    FILE* output = (level <= RUNE_LOG_WARNING) ? stderr : stdout;
    vfprintf(output, format, args);
    va_end(args);
}

// Safe memory allocation
void* rune_safe_malloc(size_t size) {
    if (size == 0) {
        rune_log_warning("Attempted to allocate 0 bytes\n");
        return NULL;
    }
    
    void* ptr = malloc(size);
    if (!ptr) {
        rune_log_error("Memory allocation failed for %zu bytes\n", size);
        return NULL;
    }
    
    // Initialize to zero for safety
    memset(ptr, 0, size);
    return ptr;
}

// Safe string duplication
char* rune_safe_strdup(const char* src, size_t max_len) {
    if (!src) {
        rune_log_warning("Attempted to duplicate NULL string\n");
        return NULL;
    }
    
    size_t len = strnlen(src, max_len);
    char* dest = rune_safe_malloc(len + 1);
    if (dest) {
        memcpy(dest, src, len);
        dest[len] = '\0';
    }
    
    return dest;
}

// Safe string to integer conversion
int rune_safe_atoi(const char* str, int* result) {
    if (!str || !result) {
        return -1;
    }
    
    char* endptr;
    long val = strtol(str, &endptr, 10);
    
    // Check for conversion errors
    if (endptr == str || *endptr != '\0') {
        return -1; // Invalid number
    }
    
    // Check for overflow
    if (val > INT_MAX || val < INT_MIN) {
        return -1; // Overflow
    }
    
    *result = (int)val;
    return 0;
}
