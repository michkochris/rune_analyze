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
#include "rune_master.h"  // 🌟 Master orchestration functions

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
    struct timespec start_time, end_time;
    
    // 🌟 MASTER ORCHESTRATION MODE CHECK (THE VISION!)
    if (g_config.master_deep_install) {
        if (g_config.dry_run_mode) {
            printf("🛡️ DRY RUN: Would execute master deep install for %s\n", g_config.master_target_package);
            return 0;
        }
        return rune_master_deep_install(g_config.master_target_package);
    }
    
    if (g_config.master_security_scan) {
        return rune_master_security_scan(g_config.master_target_package);
    }
    
    if (g_config.master_smart_monitor) {
        if (g_config.dry_run_mode) {
            printf("🛡️ DRY RUN: Would execute smart monitoring for %s\n", g_config.target_executable);
            return 0;
        }
        return rune_master_smart_monitor(g_config.target_executable);
    }
    
    if (g_config.master_threat_analyze) {
        return rune_master_threat_analyze(g_config.master_target_package);
    }
    
    // 🛡️ NEW SAFE ANALYSIS MODES
    if (g_config.master_safe_analyze) {
        return rune_safe_analyze_package(g_config.master_target_package);
    }
    
    if (g_config.master_safe_threats) {
        int risk_score = rune_safe_analyze_package(g_config.master_target_package);
        rune_safe_detect_specific_threats(g_config.master_target_package);
        return risk_score;
    }
    
    // Start timing measurement
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    // Output JSON analysis start if requested
    rune_output_json_analysis_start(rune_get_target_executable());
    
    RUNE_LOG_FUNC_START("target_execution");
    
    // Validate the target executable (skip for monitoring mode)
    if (!g_config.enable_monitoring) {
        if (rune_validate_executable(rune_get_target_executable()) != 0) {
            rune_log_error("Target executable validation failed\n");
            rune_output_json_error_report("validate_executable", "Target executable validation failed", -1);
            return -1;
        }
    } else {
        // In monitoring mode, we just log what we're about to monitor
        rune_log_info("🔍 Monitoring mode enabled for command: %s\n", rune_get_target_executable());
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
    
    // Calculate total execution time
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double execution_time = (end_time.tv_sec - start_time.tv_sec) + 
                           (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;
    
    // Update results with timing
    g_results.execution_time = execution_time;
    
    // Generate output report
    RUNE_LOG_FUNC_START("report_generation");
    switch (rune_get_output_format()) {
        case 0: // Human readable
            rune_print_human_report();
            break;
        case 1: // JSON
            rune_output_json_analysis_result(&g_results, execution_time);
            break;
        case 2: // Both
            rune_print_human_report();
            rune_output_json_analysis_result(&g_results, execution_time);
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
    printf("\nUsage: %s [options] <target>\n\n", program_name);
    
    printf("🛡️ SAFE ANALYSIS (Recommended - No System Execution):\n");
    printf("  --safe-analyze <pkg.deb>        🛡️  Static analysis without execution\n");
    printf("  --safe-threats <pkg.deb>        🔍  Enhanced threat detection (safe)\n");
    printf("  --security-scan <pkg.deb>       📊  Pre-installation security analysis\n");
    printf("  --threat-analyze <pkg.deb>      ⚖️   Comprehensive threat assessment\n\n");
    
    printf("⚠️  EXECUTION ANALYSIS (Requires -f flag for safety):\n");
    printf("  --deep-install <pkg.deb> -f     🚨  Master-controlled installation (EXECUTES!)\n");
    printf("  --smart-monitor <cmd> -f        🔧  Intelligent command monitoring (EXECUTES!)\n");
    printf("  --monitor <command> -f          📡  Classic Unix monitoring (EXECUTES!)\n\n");
    
    printf("Control Options:\n");
    printf("  -f, --force             🚨  FORCE execution mode (required for execution commands)\n");
    printf("  --dry-run              🛡️  Simulate execution without actually running\n");
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
    
    printf("✅ SAFE EXAMPLES (Recommended - No Risk):\n");
    printf("  %s --safe-analyze suspicious.deb        # Safe static analysis\n", program_name);
    printf("  %s --safe-threats malware.deb           # Safe threat detection\n", program_name);
    printf("  %s --security-scan unknown.deb          # Safe security assessment\n", program_name);
    printf("  %s --threat-analyze package.deb         # Safe threat analysis\n\n", program_name);
    
    printf("🚨 EXECUTION EXAMPLES (Requires explicit -f flag):\n");
    printf("  %s --deep-install package.deb -f        # EXECUTES - Master installation control\n", program_name);
    printf("  %s --monitor \"runepkg -i test.deb\" -f   # EXECUTES - Classic Unix monitoring\n", program_name);
    printf("  %s --smart-monitor \"cmd\" -f             # EXECUTES - Intelligent monitoring\n\n", program_name);
    
    printf("🛡️ SAFETY DESIGN:\n");
    printf("  • Safe analysis is the DEFAULT (no system execution)\n");
    printf("  • Execution commands REQUIRE explicit -f flag\n");
    printf("  • Use --dry-run to simulate execution safely\n");
    printf("  • Safe mode provides comprehensive analysis without risks\n\n");
    
    printf("Framework Foundation: Ready for expert developer enhancement\n");
}
