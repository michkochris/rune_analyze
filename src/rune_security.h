/**
 * rune_security.h - Security analysis module for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 */

#ifndef RUNE_SECURITY_H
#define RUNE_SECURITY_H

#include "rune_types.h"

// Security analysis functions
void rune_analyze_security_patterns(void);
void rune_detect_memory_vulnerabilities(void);
void rune_analyze_dangerous_functions(void);
void rune_detect_vulnerable_functions(void);
void rune_analyze_buffer_overflows(void);

// Binary analysis functions
void rune_analyze_binary_symbols(void);
int rune_run_objdump_analysis(void);
int rune_run_nm_analysis(void);
int rune_run_readelf_analysis(void);

// Debug and crash analysis
void rune_extract_debug_info(void);
void rune_parse_gdb_backtrace(void);
void rune_analyze_stack_traces(void);

// Network security analysis
void rune_analyze_network_behavior(void);
void rune_monitor_network_connections(void);
void rune_detect_outbound_requests(void);
int rune_check_network_activity(pid_t pid);

// Security trigger callbacks for checkpoint system
void rune_security_syscall_trigger(const rune_checkpoint_t *checkpoint);
void rune_security_memory_trigger(const rune_checkpoint_t *checkpoint);
void rune_security_network_trigger(const rune_checkpoint_t *checkpoint);

#endif /* RUNE_SECURITY_H */
