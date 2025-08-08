/**
 * rune_analysis.h - Core analysis engine for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 */

#ifndef RUNE_ANALYSIS_H
#define RUNE_ANALYSIS_H

#include "rune_types.h"

// Core analysis functions
int rune_execute_target(void);
int rune_validate_executable(const char* path);
int rune_sanitize_args(char** args, int argc);
long rune_get_memory_usage(pid_t pid);

// Deep analysis functions (-vv mode)
void rune_perform_deep_analysis(void);
void rune_classify_tool(void);
void rune_analyze_performance_timing(void);
void rune_analyze_output_complexity(void);
void rune_detect_behavioral_patterns(void);
void rune_calculate_efficiency_scores(void);

// Multi-language detection
void rune_detect_language_runtime(void);
void rune_analyze_java_program(void);
void rune_analyze_rust_program(void);
void rune_analyze_python_program(void);
void rune_analyze_javascript_program(void);
void rune_analyze_go_program(void);
void rune_analyze_shell_script(void);

// Utility functions
const char* rune_decode_exit_code(int exit_code);

#endif /* RUNE_ANALYSIS_H */
