/**
 * rune_framework.c - Core framework implementation for rune_analyze
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * Framework foundation - main coordination logic
 * This file coordinates all the modular components
 */

#include "rune_analyze.h"

// Global configuration and results (accessible to all modules)
rune_config_t g_config = {0};
rune_results_t g_results = {0};

// Example trigger callbacks - these will be moved to appropriate modules
void rune_example_security_trigger(const rune_checkpoint_t *checkpoint) {
    rune_log_info("Security trigger fired for: %s\n", checkpoint->id);
    // This would call security analysis functions
}

void rune_example_performance_trigger(const rune_checkpoint_t *checkpoint) {
    rune_log_info("Performance trigger fired for: %s\n", checkpoint->id);
    // This would call performance analysis functions
}

// Initialize the entire framework
int rune_initialize(int argc, char **argv) {
    // Initialize all subsystems
    rune_checkpoint_init();
    rune_trigger_init();
    
    // Parse configuration
    if (rune_config_parse_args(argc, argv) != 0) {
        return -1;
    }
    
    // Validate configuration
    if (rune_config_validate() != 0) {
        return -1;
    }
    
    // Register example triggers (these will be moved to appropriate modules)
    rune_register_trigger("SEC:*", "security_monitor", rune_example_security_trigger);
    rune_register_trigger("FUNC:*", "performance_monitor", rune_example_performance_trigger);
    rune_register_trigger("SYSCALL:*", "syscall_monitor", rune_example_security_trigger);
    
    rune_log_checkpoint("SYSTEM: framework_initialized", RUNE_CHECKPOINT_LOAD, "All subsystems ready");
    return 0;
}

// Execute the main analysis workflow
int rune_execute_analysis(void) {
    int result = 0;
    
    RUNE_LOG_FUNC_START("target_execution");
    
    // Validate the target executable
    if (rune_validate_executable(rune_get_target_executable()) != 0) {
        rune_log_error("Target executable validation failed\n");
        return -1;
    }
    
    // Execute the target and collect data
    result = rune_execute_target();
    if (result != 0) {
        rune_log_warning("Target execution completed with issues (exit code: %d)\n", result);
    }
    
    RUNE_LOG_FUNC_END("target_execution");
    
    // Perform deep analysis if enabled
    if (rune_is_deep_analysis_enabled()) {
        RUNE_LOG_FUNC_START("deep_analysis");
        rune_perform_deep_analysis();
        RUNE_LOG_FUNC_END("deep_analysis");
    }
    
    // Generate output report
    RUNE_LOG_FUNC_START("report_generation");
    switch (rune_get_output_format()) {
        case 0: // Human readable
            rune_print_human_report();
            break;
        case 1: // JSON
            rune_print_json_report();
            break;
        case 2: // Both
            rune_print_both_reports();
            break;
        default:
            rune_print_human_report();
            break;
    }
    RUNE_LOG_FUNC_END("report_generation");
    
    // Print checkpoint timeline in verbose mode
    if (rune_is_verbose_mode() >= 2) {
        rune_print_checkpoint_timeline();
    }
    
    return result;
}

// Cleanup framework resources
void rune_cleanup(void) {
    RUNE_LOG_FUNC_START("framework_cleanup");
    
    rune_config_cleanup();
    rune_trigger_cleanup();
    rune_checkpoint_cleanup();
    
    RUNE_LOG_FUNC_END("framework_cleanup");
}

// Print usage information
void rune_print_usage(const char* program_name) {
    printf("🔬 rune_analyze - Universal Linux Executable Analysis Framework v%s\n", RUNE_ANALYZE_VERSION);
    printf("\nUsage: %s [options] <executable> [args...]\n\n", program_name);
    printf("Framework Options:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -v, --verbose           Enable verbose output\n");
    printf("  -vv, --very-verbose     Enable deep analysis mode + checkpoints\n");
    printf("  -q, --quiet             Quiet mode (errors only)\n");
    printf("  --version               Show version information\n\n");
    printf("Output Formats:\n");
    printf("  --json                  Output results in JSON format\n");
    printf("  --human                 Human-readable format (default)\n");
    printf("  --both                  Output both human and JSON formats\n\n");
    printf("Analysis Modules:\n");
    printf("  --memory                Enable memory profiling\n");
    printf("  --security              Enable security analysis\n");
    printf("  --performance           Enable performance profiling\n");
    printf("  --network               Enable network behavior analysis\n");
    printf("  --all                   Enable all analysis modules\n\n");
    printf("Examples:\n");
    printf("  %s /bin/ls                    # Basic analysis\n", program_name);
    printf("  %s -vv /usr/bin/gcc --version # Deep analysis with checkpoints\n", program_name);
    printf("  %s --json /usr/bin/sort file  # JSON output for automation\n", program_name);
    printf("\nFramework Foundation: Ready for expert developer enhancement\n");
}
