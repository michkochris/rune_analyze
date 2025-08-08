/**
 * rune_performance.h - Performance analysis module for rune_analyze framework
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 */

#ifndef RUNE_PERFORMANCE_H
#define RUNE_PERFORMANCE_H

#include "rune_types.h"

// Performance analysis functions
void rune_analyze_performance_metrics(void);
void rune_monitor_memory_usage(pid_t pid);
void rune_analyze_cpu_usage(void);
void rune_analyze_io_patterns(void);

// Timing analysis
void rune_start_timing_analysis(void);
void rune_stop_timing_analysis(void);
void rune_analyze_timing_breakdown(void);

// Efficiency calculations
void rune_calculate_memory_efficiency(void);
void rune_calculate_cpu_efficiency(void);
void rune_calculate_overall_efficiency(void);

// Performance trigger callbacks for checkpoint system
void rune_performance_func_trigger(const rune_checkpoint_t *checkpoint);
void rune_performance_timing_trigger(const rune_checkpoint_t *checkpoint);

#endif /* RUNE_PERFORMANCE_H */
