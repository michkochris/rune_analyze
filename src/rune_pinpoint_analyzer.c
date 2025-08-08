/**
 * rune_pinpoint_analyzer.c - Surgical code analysis with precise location data
 * 
 * Provides function-level, line-by-line analysis with actionable intelligence
 * Perfect for identifying intentional flaws, malformed functions, and code issues
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <limits.h>
#include <unistd.h>
#include "rune_types.h"

typedef struct {
    char filename[256];
    char function_name[128];
    int line_number;
    int severity;
    char flaw_type[64];
    char description[512];
    char recommendation[256];
} PinpointFinding;

typedef struct {
    PinpointFinding findings[1000];
    int finding_count;
    char target_file[256];
} PinpointAnalysis;

/**
 * SURGICAL FUNCTION ANALYSIS
 * Analyze individual functions for intentional flaws and malformations
 */
int analyze_function_structure(const char* filename, const char* function_content, 
                              int start_line, const char* function_name, 
                              PinpointAnalysis* analysis) {
    
    int findings_added = 0;
    char* line = strtok((char*)function_content, "\n");
    int current_line = start_line;
    
    printf("🔍 SURGICAL ANALYSIS: Function '%s' in %s (line %d)\n", 
           function_name, filename, start_line);
    
    while (line != NULL && analysis->finding_count < 1000) {
        PinpointFinding* finding = &analysis->findings[analysis->finding_count];
        
        // Check for malformed function patterns
        if (strstr(line, "return") && strstr(line, ";") && 
            (strstr(line, "malloc") && !strstr(line, "free"))) {
            
            snprintf(finding->filename, sizeof(finding->filename), "%s", filename);
            snprintf(finding->function_name, sizeof(finding->function_name), "%s", function_name);
            finding->line_number = current_line;
            finding->severity = 8; // High severity
            snprintf(finding->flaw_type, sizeof(finding->flaw_type), "MEMORY_LEAK_POTENTIAL");
            snprintf(finding->description, sizeof(finding->description), 
                    "Function returns malloc'd pointer without corresponding free - potential memory leak");
            snprintf(finding->recommendation, sizeof(finding->recommendation), 
                    "Add proper memory management or document ownership transfer");
            
            analysis->finding_count++;
            findings_added++;
        }
        
        // Check for intentionally malformed error handling
        if (strstr(line, "if") && strstr(line, "==") && strstr(line, "NULL") &&
            !strstr(line, "return") && !strstr(line, "exit")) {
            
            snprintf(finding->filename, sizeof(finding->filename), "%s", filename);
            snprintf(finding->function_name, sizeof(finding->function_name), "%s", function_name);
            finding->line_number = current_line;
            finding->severity = 7;
            snprintf(finding->flaw_type, sizeof(finding->flaw_type), "MALFORMED_ERROR_HANDLING");
            snprintf(finding->description, sizeof(finding->description), 
                    "NULL check without proper error handling - intentionally malformed");
            snprintf(finding->recommendation, sizeof(finding->recommendation), 
                    "Add return statement or error handling after NULL check");
            
            analysis->finding_count++;
            findings_added++;
        }
        
        // Check for buffer overflow potential
        if (strstr(line, "strcpy") || strstr(line, "sprintf") || strstr(line, "gets")) {
            snprintf(finding->filename, sizeof(finding->filename), "%s", filename);
            snprintf(finding->function_name, sizeof(finding->function_name), "%s", function_name);
            finding->line_number = current_line;
            finding->severity = 9; // Critical
            snprintf(finding->flaw_type, sizeof(finding->flaw_type), "BUFFER_OVERFLOW_RISK");
            snprintf(finding->description, sizeof(finding->description), 
                    "Unsafe string function usage - buffer overflow potential");
            snprintf(finding->recommendation, sizeof(finding->recommendation), 
                    "Replace with safe alternatives: strncpy, snprintf, fgets");
            
            analysis->finding_count++;
            findings_added++;
        }
        
        // Check for uninitialized variable usage
        if (strstr(line, "int ") && !strstr(line, "=") && strstr(line, ";")) {
            snprintf(finding->filename, sizeof(finding->filename), "%s", filename);
            snprintf(finding->function_name, sizeof(finding->function_name), "%s", function_name);
            finding->line_number = current_line;
            finding->severity = 6;
            snprintf(finding->flaw_type, sizeof(finding->flaw_type), "UNINITIALIZED_VARIABLE");
            snprintf(finding->description, sizeof(finding->description), 
                    "Variable declared without initialization - potential undefined behavior");
            snprintf(finding->recommendation, sizeof(finding->recommendation), 
                    "Initialize variable at declaration or before first use");
            
            analysis->finding_count++;
            findings_added++;
        }
        
        line = strtok(NULL, "\n");
        current_line++;
    }
    
    return findings_added;
}

/**
 * EXTRACT FUNCTIONS FROM SOURCE FILE
 * Parse C source file and extract individual functions for analysis
 */
int extract_functions_for_analysis(const char* filepath, PinpointAnalysis* analysis) {
    FILE* file = fopen(filepath, "r");
    if (!file) {
        printf("❌ Cannot open file: %s\n", filepath);
        return -1;
    }
    
    char line[1024];
    char current_function[50000] = {0}; // Large buffer for function content
    char function_name[128] = {0};
    int line_number = 0;
    int function_start_line = 0;
    int in_function = 0;
    int brace_count = 0;
    
    printf("\n🏗️ EXTRACTING FUNCTIONS FROM: %s\n", filepath);
    printf("=====================================\n");
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Detect function start (simplified pattern)
        if (!in_function && strstr(line, "(") && strstr(line, ")") && 
            strstr(line, "{") && !strstr(line, "if") && !strstr(line, "while")) {
            
            // Extract function name (simplified)
            char* func_start = strstr(line, " ");
            char* func_end = strstr(line, "(");
            if (func_start && func_end && func_end > func_start) {
                int name_len = func_end - func_start - 1;
                if (name_len > 0 && name_len < 127) {
                    strncpy(function_name, func_start + 1, name_len);
                    function_name[name_len] = '\0';
                    
                    in_function = 1;
                    function_start_line = line_number;
                    brace_count = 1;
                    strcpy(current_function, line);
                    
                    printf("📍 Found function: %s() at line %d\n", function_name, line_number);
                }
            }
        }
        // Continue collecting function content
        else if (in_function) {
            strcat(current_function, line);
            
            // Count braces to determine function end
            for (char* p = line; *p; p++) {
                if (*p == '{') brace_count++;
                if (*p == '}') brace_count--;
            }
            
            // Function ended
            if (brace_count == 0) {
                printf("🔬 Analyzing function: %s()\n", function_name);
                int findings = analyze_function_structure(filepath, current_function, 
                                                        function_start_line, function_name, analysis);
                printf("   └── Found %d issues in %s()\n", findings, function_name);
                
                // Reset for next function
                in_function = 0;
                memset(current_function, 0, sizeof(current_function));
                memset(function_name, 0, sizeof(function_name));
            }
        }
    }
    
    fclose(file);
    return 0;
}

/**
 * GENERATE PINPOINT REPORT
 * Create detailed, actionable report with file names, line numbers, function names
 */
void generate_pinpoint_report(PinpointAnalysis* analysis, int verbose) {
    printf("\n🎯 PINPOINT ANALYSIS REPORT\n");
    printf("===========================\n");
    printf("Target: %s\n", analysis->target_file);
    printf("Total findings: %d\n\n", analysis->finding_count);
    
    // Sort findings by severity (simple bubble sort)
    for (int i = 0; i < analysis->finding_count - 1; i++) {
        for (int j = 0; j < analysis->finding_count - i - 1; j++) {
            if (analysis->findings[j].severity < analysis->findings[j+1].severity) {
                PinpointFinding temp = analysis->findings[j];
                analysis->findings[j] = analysis->findings[j+1];
                analysis->findings[j+1] = temp;
            }
        }
    }
    
    // Display findings with precise location data
    for (int i = 0; i < analysis->finding_count; i++) {
        PinpointFinding* f = &analysis->findings[i];
        
        // Severity indicators
        const char* severity_icon = "🔵";
        const char* severity_text = "LOW";
        
        if (f->severity >= 9) { severity_icon = "🔴"; severity_text = "CRITICAL"; }
        else if (f->severity >= 7) { severity_icon = "🟠"; severity_text = "HIGH"; }
        else if (f->severity >= 5) { severity_icon = "🟡"; severity_text = "MEDIUM"; }
        
        printf("%s [%s] %s\n", severity_icon, severity_text, f->flaw_type);
        printf("  📁 File: %s\n", f->filename);
        printf("  🎯 Function: %s()\n", f->function_name);
        printf("  📍 Line: %d\n", f->line_number);
        printf("  📝 Issue: %s\n", f->description);
        
        if (verbose) {
            printf("  💡 Fix: %s\n", f->recommendation);
        }
        printf("\n");
    }
    
    // Summary statistics
    int critical = 0, high = 0, medium = 0, low = 0;
    for (int i = 0; i < analysis->finding_count; i++) {
        if (analysis->findings[i].severity >= 9) critical++;
        else if (analysis->findings[i].severity >= 7) high++;
        else if (analysis->findings[i].severity >= 5) medium++;
        else low++;
    }
    
    printf("📊 SEVERITY BREAKDOWN:\n");
    printf("  🔴 Critical: %d\n", critical);
    printf("  🟠 High: %d\n", high);
    printf("  🟡 Medium: %d\n", medium);
    printf("  🔵 Low: %d\n", low);
}

/**
 * MAIN PINPOINT ANALYSIS FUNCTION
 * This is called from the main analyzer when -v verbose mode is used
 */
int rune_pinpoint_analyze(const char* target_path, int verbose) {
    PinpointAnalysis analysis = {0};
    snprintf(analysis.target_file, sizeof(analysis.target_file), "%s", target_path);
    
    printf("\n🎯 INITIATING SURGICAL CODE ANALYSIS\n");
    printf("=====================================\n");
    printf("Target: %s\n", target_path);
    printf("Mode: %s\n", verbose ? "VERBOSE (-v)" : "STANDARD");
    printf("\n");
    
    // Extract and analyze functions
    if (extract_functions_for_analysis(target_path, &analysis) != 0) {
        return -1;
    }
    
    // Generate detailed report
    generate_pinpoint_report(&analysis, verbose);
    
    return analysis.finding_count;
}
