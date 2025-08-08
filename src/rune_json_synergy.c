/*
 * RUNE_JSON_SYNERGY.C
 * Demonstrates rune_analyze orchestrating runepkg --json for structured data analysis
 * This shows how the MASTER (rune_analyze) controls the TOOL (runepkg) for JSON automation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char command[512];
    char output_buffer[16384];
    int success;
    int is_json;
} RunepkgJsonResult;

/*
 * ORCHESTRATE RUNEPKG JSON COMMANDS
 * This shows rune_analyze as the MASTER controlling runepkg via JSON
 */
int rune_orchestrate_runepkg_json(const char* json_command, RunepkgJsonResult* result) {
    printf("\n🎯 RUNE_ANALYZE: Orchestrating runepkg JSON command: %s\n", json_command);
    
    // Build the command string
    snprintf(result->command, sizeof(result->command), 
             "cd ../runepkg && %s 2>&1", json_command);
    
    // Execute and capture output
    FILE* pipe = popen(result->command, "r");
    if (!pipe) {
        printf("❌ ERROR: Failed to execute runepkg command\n");
        return 0;
    }
    
    size_t total_read = 0;
    size_t bytes_read;
    while ((bytes_read = fread(result->output_buffer + total_read, 1, 
                              sizeof(result->output_buffer) - total_read - 1, pipe)) > 0) {
        total_read += bytes_read;
    }
    result->output_buffer[total_read] = '\0';
    
    pclose(pipe);
    
    printf("📦 RUNEPKG RESPONSE (%zu bytes):\n%s\n", strlen(result->output_buffer), result->output_buffer);
    
    // Check if output looks like JSON
    char* trimmed = result->output_buffer;
    while (*trimmed == ' ' || *trimmed == '\n' || *trimmed == '\t') trimmed++;
    
    if (*trimmed == '{' || *trimmed == '[') {
        result->is_json = 1;
        printf("✅ Output detected as JSON format!\n");
    } else {
        result->is_json = 0;
        printf("ℹ️ Output is text format (not JSON)\n");
    }
    
    result->success = 1;
    return 1;
}

/*
 * ANALYZE JSON-STYLE OUTPUT
 * This shows rune_analyze intelligently processing runepkg output structure
 */
void rune_analyze_json_output(const char* output) {
    printf("\n🔍 RUNE_ANALYZE: Analyzing runepkg output structure...\n");
    
    // Look for JSON characteristics
    if (strstr(output, "{") && strstr(output, "}")) {
        printf("📋 Structure: Contains JSON object notation\n");
    }
    if (strstr(output, "[") && strstr(output, "]")) {
        printf("📋 Structure: Contains JSON array notation\n");
    }
    if (strstr(output, "\"")) {
        printf("📋 Structure: Contains quoted strings (JSON-like)\n");
    }
    if (strstr(output, ":")) {
        printf("📋 Structure: Contains key-value separators\n");
    }
    
    // Count key indicators
    int brace_count = 0;
    int quote_count = 0;
    const char* p = output;
    while (*p) {
        if (*p == '{' || *p == '}') brace_count++;
        if (*p == '"') quote_count++;
        p++;
    }
    
    printf("📊 Analysis: %d braces, %d quotes found\n", brace_count, quote_count);
}

/*
 * DEMONSTRATE COMPREHENSIVE JSON SYNERGY
 */
void demonstrate_json_synergy() {
    printf("🚀 RUNE_ANALYZE + RUNEPKG JSON SYNERGY DEMONSTRATION\n");
    printf("====================================================\n");
    
    RunepkgJsonResult result = {0};
    
    // Test 1: JSON list packages
    printf("\n🔸 TEST 1: rune_analyze orchestrates 'runepkg --json --list'\n");
    if (rune_orchestrate_runepkg_json("./runepkg --json --list", &result)) {
        rune_analyze_json_output(result.output_buffer);
    }
    
    // Test 2: JSON package info (if available)
    printf("\n🔸 TEST 2: rune_analyze orchestrates 'runepkg --json --info bash'\n");
    memset(&result, 0, sizeof(result));
    if (rune_orchestrate_runepkg_json("./runepkg --json --info bash", &result)) {
        rune_analyze_json_output(result.output_buffer);
    }
    
    // Test 3: JSON status
    printf("\n🔸 TEST 3: rune_analyze orchestrates 'runepkg --json --status'\n");
    memset(&result, 0, sizeof(result));
    if (rune_orchestrate_runepkg_json("./runepkg --json --status", &result)) {
        rune_analyze_json_output(result.output_buffer);
    }
    
    // Test 4: JSON help
    printf("\n🔸 TEST 4: rune_analyze orchestrates 'runepkg --json --help'\n");
    memset(&result, 0, sizeof(result));
    if (rune_orchestrate_runepkg_json("./runepkg --json --help", &result)) {
        rune_analyze_json_output(result.output_buffer);
    }
    
    printf("\n🎊 JSON SYNERGY COMPLETE!\n");
    printf("This shows how rune_analyze can be the MASTER orchestrating runepkg via JSON\n");
    printf("Perfect for automation, scripting, and structured data analysis!\n");
}

int main() {
    printf("🔗 RUNE_ANALYZE JSON SYNERGY DEMONSTRATION\n");
    printf("This shows the revolutionary connection between tools!\n\n");
    
    demonstrate_json_synergy();
    
    return 0;
}
