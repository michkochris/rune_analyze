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
    
    // 🌟 Master Orchestration Modes (initialized to disabled)
    g_config.master_deep_install = 0;
    g_config.master_security_scan = 0;
    g_config.master_smart_monitor = 0;
    g_config.master_threat_analyze = 0;
    
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
        else if (strcmp(argv[i], "--monitor") == 0) {
            // Classic Unix way: --monitor "command"
            if (i + 1 < argc) {
                // Store the entire command to monitor
                RUNE_SAFE_STRNCPY(g_config.target_executable, argv[i+1], sizeof(g_config.target_executable));
                g_config.enable_monitoring = 1;
                i++;
            } else {
                rune_log(0, "Error: --monitor requires a command to monitor\n");
                return -1;
            }
        }
        // 🛡️ SAFE ANALYSIS COMMANDS (New - No Execution)
        else if (strcmp(argv[i], "--safe-analyze") == 0) {
            if (i + 1 < argc) {
                RUNE_SAFE_STRNCPY(g_config.master_target_package, argv[i+1], sizeof(g_config.master_target_package));
                g_config.master_safe_analyze = 1;
                g_config.safe_mode = 1;  // Explicitly safe
                g_config.enable_security = 1;    // Enable security analysis
                i++;
            } else {
                rune_log(0, "Error: --safe-analyze requires a package path\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--safe-threats") == 0) {
            if (i + 1 < argc) {
                RUNE_SAFE_STRNCPY(g_config.master_target_package, argv[i+1], sizeof(g_config.master_target_package));
                g_config.master_safe_threats = 1;
                g_config.safe_mode = 1;  // Explicitly safe
                g_config.enable_security = 1;
                g_config.enable_deep_analysis = 1;
                i++;
            } else {
                rune_log(0, "Error: --safe-threats requires a package path\n");
                return -1;
            }
        }
        // 🌟 Master Orchestration Commands (THE VISION!) - Now require -f flag
        else if (strcmp(argv[i], "--deep-install") == 0) {
            if (i + 1 < argc) {
                RUNE_SAFE_STRNCPY(g_config.master_target_package, argv[i+1], sizeof(g_config.master_target_package));
                g_config.master_deep_install = 1;
                g_config.enable_security = 1;    // Force enable security for master mode
                g_config.enable_performance = 1; // Force enable performance
                g_config.enable_deep_analysis = 1; // Force enable deep analysis
                i++;
            } else {
                rune_log(0, "Error: --deep-install requires a .deb package path\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--security-scan") == 0) {
            if (i + 1 < argc) {
                RUNE_SAFE_STRNCPY(g_config.master_target_package, argv[i+1], sizeof(g_config.master_target_package));
                g_config.master_security_scan = 1;
                g_config.enable_security = 1;    // Force enable security analysis
                g_config.safe_mode = 1;          // Security scan is inherently safe
                i++;
            } else {
                rune_log(0, "Error: --security-scan requires a .deb package path\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--smart-monitor") == 0) {
            if (i + 1 < argc) {
                RUNE_SAFE_STRNCPY(g_config.target_executable, argv[i+1], sizeof(g_config.target_executable));
                g_config.master_smart_monitor = 1;
                g_config.enable_monitoring = 1;   // Enable monitoring
                g_config.enable_security = 1;     // Enable real-time security detection
                i++;
            } else {
                rune_log(0, "Error: --smart-monitor requires a command to monitor\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--threat-analyze") == 0) {
            if (i + 1 < argc) {
                RUNE_SAFE_STRNCPY(g_config.master_target_package, argv[i+1], sizeof(g_config.master_target_package));
                g_config.master_threat_analyze = 1;
                g_config.enable_security = 1;     // Force enable all security features
                g_config.enable_deep_analysis = 1;
                g_config.enable_network_analysis = 1;
                g_config.safe_mode = 1;           // Threat analysis is safe (no execution)
                i++;
            } else {
                rune_log(0, "Error: --threat-analyze requires a .deb package path\n");
                return -1;
            }
        }
        // 🛡️ FORCE AND CONTROL OPTIONS
        else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            g_config.force_execution = 1;
            g_config.safe_mode = 0;  // Explicit override of safe mode
        }
        else if (strcmp(argv[i], "--dry-run") == 0) {
            g_config.dry_run_mode = 1;
            g_config.safe_mode = 1;  // Dry run is inherently safe
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
    // 🛡️ FORCE EXECUTION VALIDATION
    // Check if execution commands are used without -f flag
    if ((g_config.master_deep_install || g_config.master_smart_monitor || g_config.enable_monitoring) && 
        !g_config.force_execution && !g_config.dry_run_mode) {
        
        printf("🚨 EXECUTION SAFETY BLOCK:\n");
        printf("═══════════════════════════\n");
        printf("The following commands EXECUTE code on your system:\n");
        if (g_config.master_deep_install) printf("  • --deep-install (runs actual installation)\n");
        if (g_config.master_smart_monitor) printf("  • --smart-monitor (executes monitored command)\n");
        if (g_config.enable_monitoring) printf("  • --monitor (executes monitored command)\n");
        printf("\n🛡️ FOR YOUR SAFETY:\n");
        printf("  Add -f flag to explicitly permit execution:\n");
        if (g_config.master_deep_install) printf("    ./rune_analyze --deep-install package.deb -f\n");
        if (g_config.master_smart_monitor) printf("    ./rune_analyze --smart-monitor \"command\" -f\n");
        if (g_config.enable_monitoring) printf("    ./rune_analyze --monitor \"command\" -f\n");
        printf("\n✅ OR USE SAFE ALTERNATIVES:\n");
        printf("    ./rune_analyze --safe-analyze package.deb     # Safe static analysis\n");
        printf("    ./rune_analyze --security-scan package.deb    # Safe security scan\n");
        printf("    ./rune_analyze --threat-analyze package.deb   # Safe threat assessment\n");
        printf("    ./rune_analyze --dry-run --deep-install pkg.deb # Simulate execution\n");
        printf("\nExecution blocked for your protection.\n");
        return -1;
    }
    
    // 🌟 Master modes have their own validation logic
    if (g_config.master_deep_install || g_config.master_security_scan || 
        g_config.master_threat_analyze || g_config.master_safe_analyze || 
        g_config.master_safe_threats) {
        if (strlen(g_config.master_target_package) == 0) {
            rune_log_error("No target package specified for master mode\n");
            return -1;
        }
        return 0; // Master modes are valid
    }
    
    if (g_config.master_smart_monitor) {
        if (strlen(g_config.target_executable) == 0) {
            rune_log_error("No target command specified for smart monitor\n");
            return -1;
        }
        return 0; // Smart monitor is valid
    }
    
    // Standard validation for regular modes
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

int rune_is_json_output_enabled(void) {
    return g_config.output_format == 1; // JSON only
}

int rune_is_both_output_enabled(void) {
    return g_config.output_format == 2; // Both human and JSON
}

// JSON output functions
void rune_output_json_analysis_start(const char* target_executable) {
    if (!rune_is_json_output_enabled() && !rune_is_both_output_enabled()) return;
    
    time_t now = time(NULL);
    
    if (rune_is_both_output_enabled()) {
        printf("\n=== JSON ANALYSIS START ===\n");
    }
    
    printf("{\n");
    printf("  \"rune_analyze_version\": \"%s\",\n", RUNE_ANALYZE_VERSION);
    printf("  \"operation\": \"analysis_start\",\n");
    printf("  \"timestamp\": %ld,\n", now);
    printf("  \"target_executable\": \"%s\",\n", target_executable ? target_executable : "null");
    printf("  \"analysis_config\": {\n");
    printf("    \"verbose_mode\": %d,\n", g_config.verbose_mode);
    printf("    \"output_format\": %d,\n", g_config.output_format);
    printf("    \"security_analysis\": %s,\n", g_config.enable_security ? "true" : "false");
    printf("    \"memory_analysis\": %s,\n", g_config.enable_memory ? "true" : "false");
    printf("    \"performance_analysis\": %s,\n", g_config.enable_performance ? "true" : "false");
    printf("    \"deep_analysis\": %s,\n", g_config.enable_deep_analysis ? "true" : "false");
    printf("    \"network_analysis\": %s\n", g_config.enable_network_analysis ? "true" : "false");
    printf("  }\n");
    printf("}\n");
    
    if (rune_is_both_output_enabled()) {
        printf("=== END JSON ANALYSIS START ===\n\n");
    }
}

void rune_output_json_analysis_result(const rune_results_t* results, double execution_time) {
    if (!rune_is_json_output_enabled() && !rune_is_both_output_enabled()) return;
    if (!results) return;
    
    time_t now = time(NULL);
    
    if (rune_is_both_output_enabled()) {
        printf("\n=== JSON ANALYSIS RESULT ===\n");
    }
    
    printf("{\n");
    printf("  \"rune_analyze_version\": \"%s\",\n", RUNE_ANALYZE_VERSION);
    printf("  \"operation\": \"analysis_complete\",\n");
    printf("  \"timestamp\": %ld,\n", now);
    printf("  \"target_executable\": \"%s\",\n", rune_get_target_executable());
    printf("  \"execution_result\": {\n");
    printf("    \"exit_code\": %d,\n", results->exit_code);
    printf("    \"execution_time\": %.6f,\n", results->execution_time);
    printf("    \"child_pid\": %d\n", results->child_pid);
    printf("  },\n");
    printf("  \"memory_analysis\": {\n");
    printf("    \"peak_memory_kb\": %ld,\n", results->peak_memory_kb);
    printf("    \"memory_allocations\": %d,\n", results->memory_allocations);
    printf("    \"memory_deallocations\": %d,\n", results->memory_deallocations);
    printf("    \"memory_leaks\": %d\n", results->memory_allocations - results->memory_deallocations);
    printf("  },\n");
    printf("  \"security_analysis\": {\n");
    printf("    \"buffer_overflow_risk\": %d,\n", results->buffer_overflow_risk);
    printf("    \"memory_leak_indicators\": %d,\n", results->memory_leak_indicators);
    printf("    \"use_after_free_risk\": %d,\n", results->use_after_free_risk);
    printf("    \"format_string_vuln\": %d,\n", results->format_string_vuln);
    printf("    \"null_pointer_risk\": %d,\n", results->null_pointer_risk);
    printf("    \"integer_overflow_risk\": %d,\n", results->integer_overflow_risk);
    printf("    \"uninitialized_memory_risk\": %d,\n", results->uninitialized_memory_risk);
    printf("    \"dangerous_function_count\": %d,\n", results->dangerous_function_count);
    printf("    \"security_classification\": \"%s\",\n", results->security_classification);
    printf("    \"overall_security_score\": %d,\n", results->overall_security_score);
    printf("    \"suspicious_calls\": %d\n", results->suspicious_calls);
    printf("  },\n");
    printf("  \"io_analysis\": {\n");
    printf("    \"files_opened\": %d,\n", results->files_opened);
    printf("    \"files_created\": %d,\n", results->files_created);
    printf("    \"files_modified\": %d,\n", results->files_modified);
    printf("    \"bytes_read\": %ld,\n", results->bytes_read);
    printf("    \"bytes_written\": %ld,\n", results->bytes_written);
    printf("    \"stdout_bytes\": %zu,\n", results->stdout_bytes);
    printf("    \"stderr_bytes\": %zu\n", results->stderr_bytes);
    printf("  },\n");
    printf("  \"performance_analysis\": {\n");
    printf("    \"cpu_usage_percent\": %.2f,\n", results->cpu_usage_percent);
    printf("    \"context_switches\": %ld,\n", results->context_switches);
    printf("    \"startup_time\": %.6f,\n", results->startup_time);
    printf("    \"processing_time\": %.6f,\n", results->processing_time);
    printf("    \"cleanup_time\": %.6f,\n", results->cleanup_time);
    printf("    \"resource_efficiency_score\": %d,\n", results->resource_efficiency_score);
    printf("    \"performance_category\": \"%s\"\n", results->performance_category);
    printf("  },\n");
    printf("  \"network_analysis\": {\n");
    printf("    \"network_connections\": %d,\n", results->network_connections);
    printf("    \"outbound_http_requests\": %d,\n", results->outbound_http_requests);
    printf("    \"dns_queries_made\": %d,\n", results->dns_queries_made);
    printf("    \"data_upload_detected\": %s,\n", results->data_upload_detected ? "true" : "false");
    printf("    \"package_downloads_detected\": %s,\n", results->package_downloads_detected ? "true" : "false");
    printf("    \"network_security_score\": %d,\n", results->network_security_score);
    printf("    \"suspicious_network_activity\": %s\n", results->suspicious_network_activity ? "true" : "false");
    printf("  }\n");
    printf("}\n");
    
    if (rune_is_both_output_enabled()) {
        printf("=== END JSON ANALYSIS RESULT ===\n\n");
    }
}

void rune_output_json_error_report(const char* operation, const char* error_message, int error_code) {
    if (!rune_is_json_output_enabled() && !rune_is_both_output_enabled()) return;
    
    time_t now = time(NULL);
    
    if (rune_is_both_output_enabled()) {
        printf("\n=== JSON ERROR REPORT ===\n");
    }
    
    printf("{\n");
    printf("  \"rune_analyze_version\": \"%s\",\n", RUNE_ANALYZE_VERSION);
    printf("  \"operation\": \"%s\",\n", operation ? operation : "unknown");
    printf("  \"timestamp\": %ld,\n", now);
    printf("  \"error\": {\n");
    printf("    \"code\": %d,\n", error_code);
    printf("    \"message\": \"%s\",\n", error_message ? error_message : "Unknown error");
    printf("    \"type\": \"analysis_failure\"\n");
    printf("  },\n");
    printf("  \"target_executable\": \"%s\"\n", rune_get_target_executable());
    printf("}\n");
    
    if (rune_is_both_output_enabled()) {
        printf("=== END JSON ERROR REPORT ===\n\n");
    }
}
