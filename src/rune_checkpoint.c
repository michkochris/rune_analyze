/**
 * rune_checkpoint.c - Implementation of checkpoint and trigger system
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * Core implementation of the revolutionary checkpoint system
 * Framework foundation for timeline-based analysis
 */

#include "rune_analyze.h"
#include <sys/time.h>

// Global checkpoint storage
static rune_checkpoint_t g_checkpoints[MAX_CHECKPOINTS];
static int g_checkpoint_count = 0;
static double g_start_time = 0.0;

// Global trigger storage
static rune_trigger_t g_triggers[64];
static int g_trigger_count = 0;

// Internal helper to get current timestamp
static double rune_get_current_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

// Initialize checkpoint system
void rune_checkpoint_init(void) {
    g_checkpoint_count = 0;
    g_start_time = rune_get_current_time();
    memset(g_checkpoints, 0, sizeof(g_checkpoints));
    
    // Log the initialization checkpoint
    rune_log_checkpoint("SYSTEM: checkpoint_system_initialized", "LOAD", "Framework checkpoint system ready");
}

// Cleanup checkpoint system
void rune_checkpoint_cleanup(void) {
    rune_log_checkpoint("SYSTEM: checkpoint_system_cleanup", "EXIT", "Framework checkpoint system shutdown");
    g_checkpoint_count = 0;
    g_start_time = 0.0;
}

// Core checkpoint logging function
void rune_log_checkpoint(const char* id, const char* category, const char* context) {
    double current_time = rune_get_current_time();
    rune_log_checkpoint_with_time(id, category, context, current_time - g_start_time);
}

// Checkpoint logging with specific time offset
void rune_log_checkpoint_with_time(const char* id, const char* category, const char* context, double time_offset) {
    if (g_checkpoint_count >= MAX_CHECKPOINTS) {
        // Handle overflow - for now just ignore new checkpoints
        return;
    }
    
    rune_checkpoint_t* cp = &g_checkpoints[g_checkpoint_count++];
    
    // Fill checkpoint data
    strncpy(cp->id, id ? id : "UNKNOWN", sizeof(cp->id) - 1);
    cp->id[sizeof(cp->id) - 1] = '\0';
    
    strncpy(cp->category, category ? category : "MISC", sizeof(cp->category) - 1);
    cp->category[sizeof(cp->category) - 1] = '\0';
    
    if (context) {
        strncpy(cp->context, context, sizeof(cp->context) - 1);
        cp->context[sizeof(cp->context) - 1] = '\0';
    } else {
        cp->context[0] = '\0';
    }
    
    cp->time_offset = time_offset;
    cp->trigger_fired = 0;
    
    // Create human-readable timestamp
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm* tm_info = localtime(&tv.tv_sec);
    snprintf(cp->timestamp, sizeof(cp->timestamp), "%02d:%02d:%02d.%03ld",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, tv.tv_usec / 1000);
    
    // Process any triggers for this checkpoint
    rune_process_checkpoint_triggers(cp);
}

// Get checkpoint count
int rune_get_checkpoint_count(void) {
    return g_checkpoint_count;
}

// Get specific checkpoint
const rune_checkpoint_t* rune_get_checkpoint(int index) {
    if (index < 0 || index >= g_checkpoint_count) {
        return NULL;
    }
    return &g_checkpoints[index];
}

// Print checkpoint timeline (human readable)
void rune_print_checkpoint_timeline(void) {
    printf("\n📍 Execution Timeline (%d checkpoints):\n", g_checkpoint_count);
    printf("═══════════════════════════════════════════════════════════════\n");
    
    for (int i = 0; i < g_checkpoint_count; i++) {
        const rune_checkpoint_t* cp = &g_checkpoints[i];
        printf("[%s] %s %s", cp->timestamp, cp->id, cp->trigger_fired ? "🔥" : "");
        if (cp->context[0]) {
            printf(" → %s", cp->context);
        }
        printf("\n");
    }
    printf("═══════════════════════════════════════════════════════════════\n");
}

// Export checkpoints as JSON
void rune_export_checkpoints_json(void) {
    printf("  \"checkpoints\": [\n");
    for (int i = 0; i < g_checkpoint_count; i++) {
        const rune_checkpoint_t* cp = &g_checkpoints[i];
        printf("    {\n");
        printf("      \"id\": \"%s\",\n", cp->id);
        printf("      \"timestamp\": \"%s\",\n", cp->timestamp);
        printf("      \"category\": \"%s\",\n", cp->category);
        printf("      \"time_offset\": %.6f,\n", cp->time_offset);
        printf("      \"trigger_fired\": %s", cp->trigger_fired ? "true" : "false");
        if (cp->context[0]) {
            printf(",\n      \"context\": \"%s\"", cp->context);
        }
        printf("\n    }%s\n", (i < g_checkpoint_count - 1) ? "," : "");
    }
    printf("  ],\n");
}

// Initialize trigger system
void rune_trigger_init(void) {
    g_trigger_count = 0;
    memset(g_triggers, 0, sizeof(g_triggers));
}

// Cleanup trigger system
void rune_trigger_cleanup(void) {
    g_trigger_count = 0;
}

// Register a new trigger
int rune_register_trigger(const char* pattern, const char* name, void (*callback)(const rune_checkpoint_t *)) {
    if (g_trigger_count >= 64 || !pattern || !name || !callback) {
        return -1;
    }
    
    rune_trigger_t* trigger = &g_triggers[g_trigger_count++];
    strncpy(trigger->pattern, pattern, sizeof(trigger->pattern) - 1);
    trigger->pattern[sizeof(trigger->pattern) - 1] = '\0';
    
    strncpy(trigger->name, name, sizeof(trigger->name) - 1);
    trigger->name[sizeof(trigger->name) - 1] = '\0';
    
    trigger->callback = callback;
    trigger->enabled = 1;
    
    return 0;
}

// Enable a trigger by name
void rune_enable_trigger(const char* name) {
    for (int i = 0; i < g_trigger_count; i++) {
        if (strcmp(g_triggers[i].name, name) == 0) {
            g_triggers[i].enabled = 1;
            break;
        }
    }
}

// Disable a trigger by name
void rune_disable_trigger(const char* name) {
    for (int i = 0; i < g_trigger_count; i++) {
        if (strcmp(g_triggers[i].name, name) == 0) {
            g_triggers[i].enabled = 0;
            break;
        }
    }
}

// Simple pattern matching for triggers
static int rune_pattern_match(const char* pattern, const char* text) {
    // Simple wildcard matching: "*" matches anything
    if (strcmp(pattern, "*") == 0) {
        return 1;
    }
    
    // If pattern ends with "*", match prefix
    size_t pattern_len = strlen(pattern);
    if (pattern_len > 0 && pattern[pattern_len - 1] == '*') {
        return strncmp(pattern, text, pattern_len - 1) == 0;
    }
    
    // Exact match
    return strcmp(pattern, text) == 0;
}

// Process triggers for a checkpoint
void rune_process_checkpoint_triggers(const rune_checkpoint_t* checkpoint) {
    for (int i = 0; i < g_trigger_count; i++) {
        rune_trigger_t* trigger = &g_triggers[i];
        
        if (!trigger->enabled) {
            continue;
        }
        
        if (rune_pattern_match(trigger->pattern, checkpoint->id)) {
            // Mark that this checkpoint fired a trigger
            ((rune_checkpoint_t*)checkpoint)->trigger_fired = 1;
            
            // Call the trigger callback
            trigger->callback(checkpoint);
        }
    }
}
