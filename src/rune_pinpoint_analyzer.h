/**
 * rune_pinpoint_analyzer.h - Header for surgical code analysis
 */

#ifndef RUNE_PINPOINT_ANALYZER_H
#define RUNE_PINPOINT_ANALYZER_H

// Main pinpoint analysis function
int rune_pinpoint_analyze(const char* target_path, int verbose);

// Helper functions for integration
int analyze_function_structure(const char* filename, const char* function_content, 
                              int start_line, const char* function_name, 
                              void* analysis);

int extract_functions_for_analysis(const char* filepath, void* analysis);

#endif // RUNE_PINPOINT_ANALYZER_H
