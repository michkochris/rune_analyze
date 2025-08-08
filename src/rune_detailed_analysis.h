/*
 * RUNE_DETAILED_ANALYSIS.H
 * Header for enhanced detailed analysis with function-level reporting
 */

#ifndef RUNE_DETAILED_ANALYSIS_H
#define RUNE_DETAILED_ANALYSIS_H

// Main detailed analysis function
int rune_detailed_analyze(const char* target_path, int verbose);

// Analysis structures
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

#endif // RUNE_DETAILED_ANALYSIS_H
