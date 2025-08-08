/**
 * rune_config.c - Configuration management implementation
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 */

#include "rune_analyze.h"

// Initialize configuration with defaults
int rune_config_init(void) {
    memset(&g_config, 0, sizeof(g_config));
    
    // Set defaults
    g_config.verbose_mode = 1;          // Normal verbosity
    g_config.output_format = 0;         // Human readable
    g_config.enable_security = 1;       // Enable by default
    g_config.enable_memory = 1;         // Enable by default
    g_config.enable_performance = 1;    // Enable by default
    g_config.enable_deep_analysis = 0;  // Disabled by default
    
    return 0;
}

// Parse command line arguments
int rune_config_parse_args(int argc, char **argv) {
    if (argc < 2) {
        rune_print_usage(argv[0]);
        return -1;
    }
    
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            rune_print_usage(argv[0]);
            exit(0);
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_config.verbose_mode = 2;
        }
        else if (strcmp(argv[i], "-vv") == 0 || strcmp(argv[i], "--very-verbose") == 0) {
            g_config.verbose_mode = 3;
            g_config.enable_deep_analysis = 1;
        }
        else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            g_config.verbose_mode = 0;
        }
        else if (strcmp(argv[i], "--json") == 0) {
            g_config.output_format = 1;
        }
        else if (strcmp(argv[i], "--both") == 0) {
            g_config.output_format = 2;
        }
        else if (strcmp(argv[i], "--version") == 0) {
            printf("rune_analyze version %s\n", RUNE_ANALYZE_VERSION);
            exit(0);
        }
        else if (argv[i][0] != '-') {
            // Found the target executable
            RUNE_SAFE_STRNCPY(g_config.target_executable, argv[i], sizeof(g_config.target_executable));
            
            // Store remaining arguments
            g_config.target_argc = argc - i;
            g_config.target_args = &argv[i];
            break;
        }
    }
    
    return 0;
}

// Validate configuration
int rune_config_validate(void) {
    if (strlen(g_config.target_executable) == 0) {
        rune_log_error("No target executable specified\n");
        return -1;
    }
    
    return 0;
}

// Cleanup configuration
void rune_config_cleanup(void) {
    // Currently no dynamic memory to clean up
}

// Configuration accessors
const char* rune_get_target_executable(void) {
    return g_config.target_executable;
}

char** rune_get_target_args(void) {
    return g_config.target_args;
}

int rune_get_target_argc(void) {
    return g_config.target_argc;
}

int rune_is_verbose_mode(void) {
    return g_config.verbose_mode;
}

int rune_is_deep_analysis_enabled(void) {
    return g_config.enable_deep_analysis;
}

int rune_get_output_format(void) {
    return g_config.output_format;
}
