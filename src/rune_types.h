/**
 * rune_types.h - Core data structures for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * Framework foundation data structures
 */

#ifndef RUNE_TYPES_H
#define RUNE_TYPES_H

#include <sys/types.h>
#include <limits.h>

// Analysis result structure - comprehensive data collection
typedef struct rune_results {
    // Basic execution info
    double execution_time;
    int exit_code;
    pid_t child_pid;
    
    // Memory analysis
    long peak_memory_kb;
    int memory_allocations;
    int memory_deallocations;
    
    // I/O analysis  
    int files_opened;
    int files_created;
    int files_modified;
    long bytes_read;
    long bytes_written;
    
    // Security analysis
    int privilege_changes;
    int network_connections;
    int suspicious_calls;
    
    // Enhanced security analysis
    int buffer_overflow_risk;
    int memory_leak_indicators;
    int use_after_free_risk;
    int format_string_vuln;
    int null_pointer_risk;
    int integer_overflow_risk;
    int uninitialized_memory_risk;
    int dangerous_function_count;
    char security_classification[64];
    int overall_security_score;
    
    // Output analysis
    size_t stdout_bytes;
    size_t stderr_bytes;
    int verbose_messages;
    int error_messages;
    int warning_messages;
    
    // Deep analysis (for -vv mode)
    char tool_classification[64];
    char behavior_pattern[128];
    double startup_time;
    double processing_time;
    double cleanup_time;
    int output_complexity_score;
    int resource_efficiency_score;
    char performance_category[32];
    
    // Advanced pattern detection
    int structured_output_detected;
    int interactive_features;
    int file_format_conversions;
    int parallel_processing_hints;
    
    // Verbose Output Intelligence
    int file_operations_detected;
    int progress_indicators;
    int path_manipulations;
    int network_operations;
    int compression_operations;
    int compilation_steps;
    int database_operations;
    int system_calls_verbose;
    char verbose_operation_type[64];
    int verbose_intelligence_score;
    
    // Performance metrics
    double cpu_usage_percent;
    long context_switches;
    
    // Vulnerability Analysis
    char vulnerable_functions[10][64];
    int vulnerable_function_count;
    char crash_function[64];
    int crash_line_number;
    char source_file[256];
    char vulnerability_details[512];
    int has_debug_symbols;
    char stack_trace[1024];
    
    // Multi-Language Runtime Analysis
    char detected_language[32];
    char runtime_version[64];
    char language_specific_info[256];
    char detected_frameworks[512];
    int uses_managed_memory;
    int uses_unsafe_code;
    int jvm_analysis_available;
    int cargo_project_detected;
    char dependency_manager[32];
    
    // Network Behavior Analysis
    int network_connections_detected;
    int outbound_http_requests;
    int dns_queries_made;
    char external_hosts_contacted[512];
    int data_upload_detected;
    int package_downloads_detected;
    char repository_urls[512];
    int network_security_score;
    char network_behavior_summary[256];
    int suspicious_network_activity;
    
} rune_results_t;

// Global configuration structure
typedef struct rune_config {
    int verbose_mode;           // 0=quiet, 1=normal, 2=verbose, 3=very-verbose
    int output_format;          // 0=human, 1=json, 2=both
    int enable_security;        // Enable security analysis
    int enable_memory;          // Enable memory profiling
    int enable_io;             // Enable I/O monitoring
    int enable_performance;     // Enable performance profiling
    int enable_deep_analysis;   // Enable deep analysis (auto-enabled in -vv mode)
    int enable_network_analysis; // Enable network behavior analysis
    char target_executable[PATH_MAX];
    char **target_args;
    int target_argc;
} rune_config_t;

// Checkpoint structure for execution timeline analysis
typedef struct rune_checkpoint {
    char id[64];                // e.g. "SYSCALL: open", "FUNC: main"
    char timestamp[32];         // Human readable timestamp
    char category[16];          // PERF, MEM, SEC, etc.
    char context[128];          // Optional message/context
    double time_offset;         // Time from program start
    int trigger_fired;          // Whether this checkpoint triggered analysis
} rune_checkpoint_t;

// Analysis trigger structure
typedef struct rune_trigger {
    char pattern[64];           // Pattern to match (e.g., "SYSCALL:*", "FUNC:main")
    char name[32];              // Human name for this trigger
    void (*callback)(const rune_checkpoint_t *checkpoint);  // Function to call
    int enabled;                // Whether this trigger is active
} rune_trigger_t;

#endif /* RUNE_TYPES_H */
