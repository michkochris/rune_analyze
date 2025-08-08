/**
 * main.c - Main entry point for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * Framework foundation - clean entry point for expert developer handoff
 * Universal Linux Executable Analysis Framework
 *
 * This program is free software under GPL v3 License.
 */

#include "rune_analyze.h"

// Framework entry point
int main(int argc, char **argv) {
    int result = 0;
    
    // Initialize the framework
    RUNE_LOG_FUNC_START("main");
    rune_log_checkpoint("SYSTEM: framework_start", RUNE_CHECKPOINT_LOAD, "rune_analyze framework initialized");
    
    if (rune_initialize(argc, argv) != 0) {
        rune_log_error("Framework initialization failed\n");
        return 1;
    }
    
    // Execute the analysis
    RUNE_LOG_FUNC_START("analysis_execution");
    
    // Use enhanced verbose analysis for verbose mode, standard analysis otherwise
    if (rune_is_verbose_mode()) {
        result = rune_execute_enhanced_verbose_analysis();
    } else {
        result = rune_execute_analysis();
    }
    
    RUNE_LOG_FUNC_END("analysis_execution");
    
    // Cleanup and exit
    rune_cleanup();
    RUNE_LOG_FUNC_END("main");
    rune_log_checkpoint("SYSTEM: framework_exit", RUNE_CHECKPOINT_EXIT, "rune_analyze framework shutdown");
    
    return result;
}
