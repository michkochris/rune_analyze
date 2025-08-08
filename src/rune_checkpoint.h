/**
 * rune_checkpoint.h - Checkpoint and trigger system for rune_analyze
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * Revolutionary checkpoint-based execution analysis system
 * Foundation for the framework's timeline analysis capabilities
 */

#ifndef RUNE_CHECKPOINT_H
#define RUNE_CHECKPOINT_H

#include "rune_types.h"

// Checkpoint management functions
void rune_checkpoint_init(void);
void rune_checkpoint_cleanup(void);

// Core checkpoint logging
void rune_log_checkpoint(const char* id, const char* category, const char* context);
void rune_log_checkpoint_with_time(const char* id, const char* category, const char* context, double time_offset);

// Checkpoint analysis and retrieval
int rune_get_checkpoint_count(void);
const rune_checkpoint_t* rune_get_checkpoint(int index);
void rune_print_checkpoint_timeline(void);
void rune_export_checkpoints_json(void);

// Trigger system - event-driven analysis
void rune_trigger_init(void);
void rune_trigger_cleanup(void);
int rune_register_trigger(const char* pattern, const char* name, void (*callback)(const rune_checkpoint_t *));
void rune_enable_trigger(const char* name);
void rune_disable_trigger(const char* name);
void rune_process_checkpoint_triggers(const rune_checkpoint_t* checkpoint);

// Built-in checkpoint categories
#define RUNE_CHECKPOINT_LOAD     "LOAD"
#define RUNE_CHECKPOINT_FUNC     "FUNC"
#define RUNE_CHECKPOINT_SYSCALL  "SYSCALL"
#define RUNE_CHECKPOINT_MEM      "MEM"
#define RUNE_CHECKPOINT_NET      "NET"
#define RUNE_CHECKPOINT_SEC      "SEC"
#define RUNE_CHECKPOINT_PERF     "PERF"
#define RUNE_CHECKPOINT_EXIT     "EXIT"

// Convenience macros for checkpoint logging
#define RUNE_LOG_FUNC_START(name) rune_log_checkpoint("FUNC: " name " started", RUNE_CHECKPOINT_FUNC, NULL)
#define RUNE_LOG_FUNC_END(name) rune_log_checkpoint("FUNC: " name " completed", RUNE_CHECKPOINT_FUNC, NULL)
#define RUNE_LOG_SYSCALL(name) rune_log_checkpoint("SYSCALL: " name, RUNE_CHECKPOINT_SYSCALL, NULL)
#define RUNE_LOG_MEMORY(action) rune_log_checkpoint("MEM: " action, RUNE_CHECKPOINT_MEM, NULL)
#define RUNE_LOG_SECURITY(issue) rune_log_checkpoint("SEC: " issue, RUNE_CHECKPOINT_SEC, NULL)

#endif /* RUNE_CHECKPOINT_H */
