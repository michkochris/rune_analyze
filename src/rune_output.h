/**
 * rune_output.h - Output formatting module for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 */

#ifndef RUNE_OUTPUT_H
#define RUNE_OUTPUT_H

#include "rune_types.h"

// Output formatting functions
void rune_print_human_report(void);
void rune_print_json_report(void);
void rune_print_both_reports(void);

// Report components
void rune_print_banner(void);
void rune_print_execution_summary(void);
void rune_print_memory_analysis(void);
void rune_print_io_analysis(void);
void rune_print_security_analysis(void);
void rune_print_deep_analysis(void);

// JSON components
void rune_print_json_header(void);
void rune_print_json_execution(void);
void rune_print_json_memory(void);
void rune_print_json_security(void);
void rune_print_json_deep_analysis(void);
void rune_print_json_footer(void);

// Utility output functions
void rune_print_colored_status(const char* status, int success);
void rune_print_progress_bar(int percentage);

#endif /* RUNE_OUTPUT_H */
