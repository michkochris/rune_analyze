/*
 * RUNE_DETAILED_ANALYSIS.C
 * Enhanced verbose analysis with function names, line numbers, and file names
 * Provides human-readable, actionable output for code analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>

typedef struct {
    char function_name[256];
    char file_name[512];
    int line_number;
    char issue_type[128];
    char description[512];
    char severity[32];
    char recommendation[512];
} CodeIssue;

typedef struct {
    CodeIssue issues[1000];
    int issue_count;
    int files_analyzed;
    int functions_analyzed;
    int total_lines;
} DetailedAnalysisReport;

/*
 * DETAILED SOURCE CODE ANALYSIS
 * Analyzes C source files for function-level issues
 */
int analyze_c_source_file(const char* filepath, DetailedAnalysisReport* report) {
    FILE* file = fopen(filepath, "r");
    if (!file) {
        printf("⚠️  Cannot open file: %s\n", filepath);
        return 0;
    }
    
    char line[2048];
    int line_num = 0;
    char current_function[256] = "global";
    int in_function = 0;
    
    printf("📄 Analyzing: %s\n", filepath);
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        report->total_lines++;
        
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Detect function definitions
        if (strstr(line, "(") && strstr(line, ")") && 
            !strstr(line, "//") && !strstr(line, "/*") &&
            !strstr(line, "#include") && !strstr(line, "#define")) {
            
            // Look for function pattern: type function_name(
            char* paren = strstr(line, "(");
            if (paren) {
                char* start = paren;
                while (start > line && (isalnum(*(start-1)) || *(start-1) == '_')) {
                    start--;
                }
                if (start != paren) {
                    char temp_name[256];
                    int name_len = paren - start;
                    if (name_len < 255) {
                        strncpy(temp_name, start, name_len);
                        temp_name[name_len] = 0;
                        
                        // Filter out obvious non-functions
                        if (strcmp(temp_name, "if") != 0 && strcmp(temp_name, "while") != 0 &&
                            strcmp(temp_name, "for") != 0 && strcmp(temp_name, "switch") != 0) {
                            strcpy(current_function, temp_name);
                            in_function = 1;
                            report->functions_analyzed++;
                            printf("  🔍 Function: %s() at line %d\n", current_function, line_num);
                        }
                    }
                }
            }
        }
        
        // Check for potential issues
        CodeIssue* issue = NULL;
        
        // Buffer overflow risks
        if (strstr(line, "strcpy") || strstr(line, "strcat") || strstr(line, "sprintf")) {
            issue = &report->issues[report->issue_count++];
            strcpy(issue->function_name, current_function);
            strcpy(issue->file_name, filepath);
            issue->line_number = line_num;
            strcpy(issue->issue_type, "BUFFER_OVERFLOW_RISK");
            strcpy(issue->severity, "HIGH");
            snprintf(issue->description, sizeof(issue->description), 
                    "Unsafe string function detected: %s", line);
            strcpy(issue->recommendation, "Use safer alternatives like strncpy, strncat, snprintf");
        }
        
        // Memory management issues
        else if (strstr(line, "malloc") && !strstr(line, "free")) {
            issue = &report->issues[report->issue_count++];
            strcpy(issue->function_name, current_function);
            strcpy(issue->file_name, filepath);
            issue->line_number = line_num;
            strcpy(issue->issue_type, "MEMORY_LEAK_RISK");
            strcpy(issue->severity, "MEDIUM");
            snprintf(issue->description, sizeof(issue->description), 
                    "Memory allocation without visible free: %s", line);
            strcpy(issue->recommendation, "Ensure proper memory deallocation with free()");
        }
        
        // Privilege escalation risks
        else if (strstr(line, "system(") || strstr(line, "exec")) {
            issue = &report->issues[report->issue_count++];
            strcpy(issue->function_name, current_function);
            strcpy(issue->file_name, filepath);
            issue->line_number = line_num;
            strcpy(issue->issue_type, "PRIVILEGE_ESCALATION");
            strcpy(issue->severity, "CRITICAL");
            snprintf(issue->description, sizeof(issue->description), 
                    "System command execution detected: %s", line);
            strcpy(issue->recommendation, "Validate and sanitize all inputs, use safer alternatives");
        }
        
        // File operation risks
        else if (strstr(line, "fopen") && strstr(line, "\"w")) {
            issue = &report->issues[report->issue_count++];
            strcpy(issue->function_name, current_function);
            strcpy(issue->file_name, filepath);
            issue->line_number = line_num;
            strcpy(issue->issue_type, "FILE_WRITE_OPERATION");
            strcpy(issue->severity, "MEDIUM");
            snprintf(issue->description, sizeof(issue->description), 
                    "File write operation: %s", line);
            strcpy(issue->recommendation, "Verify file permissions and path validation");
        }
        
        // Network operations
        else if (strstr(line, "socket") || strstr(line, "connect") || strstr(line, "bind")) {
            issue = &report->issues[report->issue_count++];
            strcpy(issue->function_name, current_function);
            strcpy(issue->file_name, filepath);
            issue->line_number = line_num;
            strcpy(issue->issue_type, "NETWORK_OPERATION");
            strcpy(issue->severity, "HIGH");
            snprintf(issue->description, sizeof(issue->description), 
                    "Network operation detected: %s", line);
            strcpy(issue->recommendation, "Implement proper network security and error handling");
        }
        
        if (issue && report->issue_count >= 1000) break; // Prevent overflow
    }
    
    fclose(file);
    report->files_analyzed++;
    return 1;
}

/*
 * ANALYZE DIRECTORY OF SOURCE FILES
 */
int analyze_source_directory(const char* dir_path, DetailedAnalysisReport* report) {
    DIR* dir = opendir(dir_path);
    if (!dir) {
        printf("❌ Cannot open directory: %s\n", dir_path);
        return 0;
    }
    
    printf("\n📂 Scanning directory: %s\n", dir_path);
    printf("" "="*50 "\n");
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".c") && strlen(entry->d_name) > 2) {
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);
            analyze_c_source_file(filepath, report);
        }
    }
    
    closedir(dir);
    return 1;
}

/*
 * GENERATE DETAILED HUMAN-READABLE REPORT
 */
void generate_detailed_report(DetailedAnalysisReport* report, const char* target) {
    printf("\n");
    printf("" "="*80 "\n");
    printf("🔬 DETAILED CODE ANALYSIS REPORT\n");
    printf("" "="*80 "\n");
    printf("📁 Target: %s\n", target);
    printf("📊 Files analyzed: %d\n", report->files_analyzed);
    printf("⚙️  Functions analyzed: %d\n", report->functions_analyzed);
    printf("📝 Total lines: %d\n", report->total_lines);
    printf("🚨 Issues found: %d\n", report->issue_count);
    printf("\n");
    
    if (report->issue_count == 0) {
        printf("✅ No significant issues detected!\n");
        return;
    }
    
    // Group issues by severity
    printf("🚨 CRITICAL ISSUES:\n");
    printf("" "-"*40 "\n");
    for (int i = 0; i < report->issue_count; i++) {
        if (strcmp(report->issues[i].severity, "CRITICAL") == 0) {
            printf("❗ %s:%d in %s()\n", 
                   strrchr(report->issues[i].file_name, '/') ? 
                   strrchr(report->issues[i].file_name, '/') + 1 : report->issues[i].file_name,
                   report->issues[i].line_number,
                   report->issues[i].function_name);
            printf("   Type: %s\n", report->issues[i].issue_type);
            printf("   Issue: %s\n", report->issues[i].description);
            printf("   💡 Fix: %s\n", report->issues[i].recommendation);
            printf("\n");
        }
    }
    
    printf("⚠️  HIGH PRIORITY ISSUES:\n");
    printf("" "-"*40 "\n");
    for (int i = 0; i < report->issue_count; i++) {
        if (strcmp(report->issues[i].severity, "HIGH") == 0) {
            printf("⚠️  %s:%d in %s()\n", 
                   strrchr(report->issues[i].file_name, '/') ? 
                   strrchr(report->issues[i].file_name, '/') + 1 : report->issues[i].file_name,
                   report->issues[i].line_number,
                   report->issues[i].function_name);
            printf("   Type: %s\n", report->issues[i].issue_type);
            printf("   Issue: %s\n", report->issues[i].description);
            printf("   💡 Fix: %s\n", report->issues[i].recommendation);
            printf("\n");
        }
    }
    
    printf("ℹ️  MEDIUM PRIORITY ISSUES:\n");
    printf("" "-"*40 "\n");
    for (int i = 0; i < report->issue_count; i++) {
        if (strcmp(report->issues[i].severity, "MEDIUM") == 0) {
            printf("ℹ️  %s:%d in %s()\n", 
                   strrchr(report->issues[i].file_name, '/') ? 
                   strrchr(report->issues[i].file_name, '/') + 1 : report->issues[i].file_name,
                   report->issues[i].line_number,
                   report->issues[i].function_name);
            printf("   Type: %s\n", report->issues[i].issue_type);
            printf("   Issue: %s\n", report->issues[i].description);
            printf("   💡 Fix: %s\n", report->issues[i].recommendation);
            printf("\n");
        }
    }
    
    printf("" "="*80 "\n");
    printf("🎯 SUMMARY AND RECOMMENDATIONS:\n");
    printf("" "="*80 "\n");
    
    int critical = 0, high = 0, medium = 0;
    for (int i = 0; i < report->issue_count; i++) {
        if (strcmp(report->issues[i].severity, "CRITICAL") == 0) critical++;
        else if (strcmp(report->issues[i].severity, "HIGH") == 0) high++;
        else if (strcmp(report->issues[i].severity, "MEDIUM") == 0) medium++;
    }
    
    printf("📈 Issue Breakdown: %d Critical, %d High, %d Medium\n", critical, high, medium);
    
    if (critical > 0) {
        printf("🚨 IMMEDIATE ACTION REQUIRED: %d critical security issues found\n", critical);
        printf("   → Review and fix critical issues before deployment\n");
    }
    if (high > 0) {
        printf("⚠️  HIGH PRIORITY: %d high-risk issues need attention\n", high);
        printf("   → Address high-priority issues in next development cycle\n");
    }
    if (medium > 0) {
        printf("📝 MEDIUM PRIORITY: %d medium-risk improvements recommended\n", medium);
        printf("   → Consider addressing in future updates\n");
    }
    
    printf("\n🔧 Next Steps:\n");
    printf("1. Review each critical and high-priority issue\n");
    printf("2. Apply recommended fixes\n");
    printf("3. Re-run analysis to verify fixes\n");
    printf("4. Consider code review for remaining issues\n");
}

/*
 * MAIN DETAILED ANALYSIS FUNCTION
 */
int rune_detailed_analyze(const char* target_path, int verbose) {
    printf("🔍 DETAILED CODE ANALYSIS STARTING\n");
    printf("" "="*50 "\n");
    printf("🎯 Target: %s\n", target_path);
    printf("📊 Verbosity: %s\n", verbose ? "ENABLED" : "DISABLED");
    printf("\n");
    
    DetailedAnalysisReport report = {0};
    
    struct stat statbuf;
    if (stat(target_path, &statbuf) == 0) {
        if (S_ISDIR(statbuf.st_mode)) {
            analyze_source_directory(target_path, &report);
        } else {
            analyze_c_source_file(target_path, &report);
        }
    } else {
        printf("❌ Cannot access target: %s\n", target_path);
        return 1;
    }
    
    if (verbose) {
        generate_detailed_report(&report, target_path);
    } else {
        printf("📊 Quick Summary: %d files, %d functions, %d issues\n", 
               report.files_analyzed, report.functions_analyzed, report.issue_count);
    }
    
    return 0;
}
