#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * DEMONSTRATION: Pinpoint Analysis with Function Names, Line Numbers, File Names
 * This shows exactly what you want - precise location of issues in code
 */

void analyze_runepkg_source_file(const char* filepath) {
    printf("\n🔍 SURGICAL ANALYSIS: %s\n", filepath);
    printf("=====================================\n");
    
    FILE* file = fopen(filepath, "r");
    if (!file) {
        printf("❌ Cannot analyze %s\n", filepath);
        return;
    }
    
    char line[1024];
    int line_number = 0;
    char current_function[128] = "global_scope";
    int issues_found = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Detect function names (simplified)
        if (strstr(line, "(") && strstr(line, ")") && strstr(line, "{") && 
            !strstr(line, "if") && !strstr(line, "while") && !strstr(line, "printf")) {
            
            // Extract function name (very simplified)
            char* space = strstr(line, " ");
            char* paren = strstr(line, "(");
            if (space && paren && paren > space) {
                int len = paren - space - 1;
                if (len > 0 && len < 127) {
                    strncpy(current_function, space + 1, len);
                    current_function[len] = '\0';
                }
            }
            printf("📍 Found function: %s() at line %d\n", current_function, line_number);
        }
        
        // PINPOINT ANALYSIS - Look for specific issues
        
        // 1. Memory leak potential
        if (strstr(line, "malloc") && !strstr(line, "free")) {
            printf("🔴 [CRITICAL] MEMORY_LEAK_POTENTIAL\n");
            printf("  📁 File: %s\n", filepath);
            printf("  🎯 Function: %s()\n", current_function);
            printf("  📍 Line: %d\n", line_number);
            printf("  📝 Issue: malloc without corresponding free\n");
            printf("  💡 Fix: Add proper memory management\n\n");
            issues_found++;
        }
        
        // 2. Buffer overflow risk
        if (strstr(line, "strcpy") || strstr(line, "sprintf") || strstr(line, "gets")) {
            printf("🔴 [CRITICAL] BUFFER_OVERFLOW_RISK\n");
            printf("  📁 File: %s\n", filepath);
            printf("  🎯 Function: %s()\n", current_function);
            printf("  📍 Line: %d\n", line_number);
            printf("  📝 Issue: Unsafe string function usage\n");
            printf("  💡 Fix: Use strncpy, snprintf, or fgets\n\n");
            issues_found++;
        }
        
        // 3. Intentional malformation - NULL check without handling
        if (strstr(line, "if") && strstr(line, "== NULL") && 
            !strstr(line, "return") && !strstr(line, "exit")) {
            printf("🟠 [HIGH] MALFORMED_ERROR_HANDLING\n");
            printf("  📁 File: %s\n", filepath);
            printf("  🎯 Function: %s()\n", current_function);
            printf("  📍 Line: %d\n", line_number);
            printf("  📝 Issue: NULL check without error handling\n");
            printf("  💡 Fix: Add return or proper error handling\n\n");
            issues_found++;
        }
        
        // 4. Uninitialized variable
        if (strstr(line, "int ") && !strstr(line, "=") && strstr(line, ";")) {
            printf("🟡 [MEDIUM] UNINITIALIZED_VARIABLE\n");
            printf("  📁 File: %s\n", filepath);
            printf("  🎯 Function: %s()\n", current_function);
            printf("  📍 Line: %d\n", line_number);
            printf("  📝 Issue: Variable declared without initialization\n");
            printf("  💡 Fix: Initialize at declaration\n\n");
            issues_found++;
        }
    }
    
    fclose(file);
    
    printf("📊 ANALYSIS COMPLETE: %d issues found in %s\n", issues_found, filepath);
}

int main(int argc, char *argv[]) {
    printf("🎯 RUNEPKG PINPOINT ANALYSIS DEMONSTRATION\n");
    printf("==========================================\n");
    printf("This shows EXACTLY what you want:\n");
    printf("  📁 Exact file names\n");
    printf("  🎯 Specific function names\n");
    printf("  📍 Precise line numbers\n");
    printf("  📝 Issue descriptions\n");
    printf("  💡 Actionable recommendations\n\n");
    
    // Analyze some runepkg source files
    const char* runepkg_files[] = {
        "../runepkg/runepkg_cli.c",
        "../runepkg/runepkg_config.c", 
        "../runepkg/runepkg_defensive.c",
        NULL
    };
    
    for (int i = 0; runepkg_files[i] != NULL; i++) {
        analyze_runepkg_source_file(runepkg_files[i]);
    }
    
    printf("\n🎊 This demonstrates the pinpoint analysis you want!\n");
    printf("Each finding shows file, function, line number, and actionable fix.\n");
    
    return 0;
}
