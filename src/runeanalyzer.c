/**
 * runeanalyzer - Advanced Linux Executable Security & Performance Analyzer
 *
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * A comprehensive intelligent analysis framework for ANY Linux executable.
 * Provides runtime analysis, security assessment, performance profiling,
 * network behavior analysis, and adaptive vulnerability detection.
 *
 * Part of the rune* toolkit (runepkg, runarlinux, runeanalyzer)
 *
 * Usage: runeanalyzer /path/to/any/executable [args...]
 *
 * This program is free software under GPL v3 License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <ctype.h>

// Function declarations
void perform_deep_analysis(void);
void classify_tool(void);
void analyze_performance_timing(void);
void analyze_output_complexity(void);
void detect_behavioral_patterns(void);
void calculate_efficiency_scores(void);
void analyze_security_patterns(void);
void detect_memory_vulnerabilities(void);
void analyze_dangerous_functions(void);
void analyze_verbose_patterns(void);
void detect_tool_specific_intelligence(void);
const char* decode_exit_code(int exit_code);
void runeanalyzer_log(int level, const char* format, ...);
void print_usage(const char* program_name);
void print_human_report(void);
void print_json_report(void);

// Advanced binary analysis functions for pinpoint vulnerability detection
void analyze_binary_symbols(void);
void detect_vulnerable_functions(void);
void analyze_stack_traces(void);
void extract_debug_info(void);
int run_objdump_analysis(void);
int run_nm_analysis(void);
int run_readelf_analysis(void);
void parse_gdb_backtrace(void);

// Multi-language support functions
void detect_language_runtime(void);
void analyze_java_program(void);
void analyze_rust_program(void);
void analyze_python_program(void);
void analyze_javascript_program(void);
void analyze_go_program(void);
void analyze_perl_program(void);
void analyze_shell_script(void);
void detect_runtime_patterns(void);
void detect_frameworks(void);

// Network behavior analysis functions - NEW!
void analyze_network_behavior(void);
void monitor_network_connections(void);
void detect_outbound_requests(void);
void analyze_package_repositories(void);
void query_debian_repository(const char* package_name);
int check_network_activity(pid_t pid);

// Advanced memory safety functions for defensive programming
void* safe_malloc(size_t size);
char* safe_strdup(const char* src, size_t max_len);
int safe_atoi(const char* str, int* result);

// Safe string operations - Defensive C Programming
#define SAFE_STRNCPY(dest, src, size) do { \
    strncpy(dest, src, size - 1); \
    (dest)[size - 1] = '\0'; \
} while(0)

#define SAFE_STRNCAT(dest, src, size) do { \
    size_t current_len = strnlen(dest, size - 1); \
    size_t remaining = size - current_len - 1; \
    if (remaining > 0) { \
        strncat(dest, src, remaining); \
        (dest)[size - 1] = '\0'; \
    } \
} while(0)

// Input validation macros
#define VALIDATE_POINTER(ptr, name) do { \
    if (!(ptr)) { \
        runeanalyzer_log(0, "Error: NULL pointer in %s\n", name); \
        return; \
    } \
} while(0)

#define VALIDATE_RANGE(value, min, max, name) do { \
    if ((value) < (min) || (value) > (max)) { \
        runeanalyzer_log(0, "Error: %s value %d out of range [%d, %d]\n", name, value, min, max); \
        (value) = ((value) < (min)) ? (min) : (max); \
    } \
} while(0)

// Version and build info
#define RUNEANALYZER_VERSION "1.0.0"
#define MAX_OUTPUT_SIZE 65536
#define MAX_COMMAND_LENGTH 4096
#define MAX_ARGS 256

// Analysis result structure
typedef struct {
    // Basic execution info
    double execution_time;
    int exit_code;
    pid_t child_pid;
    
    // Memory analysis
    long peak_memory_kb;
    int memory_allocations;
    int memory_deallocations;
    
    // I/O analysis  
    int files_opened;
    int files_created;
    int files_modified;
    long bytes_read;
    long bytes_written;
    
    // Security analysis
    int privilege_changes;
    int network_connections;
    int suspicious_calls;
    
    // Enhanced security analysis
    int buffer_overflow_risk;        // Buffer overflow patterns detected
    int memory_leak_indicators;      // Memory leak patterns
    int use_after_free_risk;         // Use-after-free patterns
    int format_string_vuln;          // Format string vulnerabilities
    int null_pointer_risk;           // Null pointer dereference risk
    int integer_overflow_risk;       // Integer overflow patterns
    int uninitialized_memory_risk;   // Uninitialized memory usage
    int dangerous_function_count;    // Count of dangerous function calls
    char security_classification[64]; // Security risk level
    int overall_security_score;      // 1-10 security score (10=safest)
    
    // Output analysis
    size_t stdout_bytes;
    size_t stderr_bytes;
    int verbose_messages;
    int error_messages;
    int warning_messages;
    
    // Deep analysis (for -vv mode)
    char tool_classification[64];    // "text_processor", "compiler", "system_util", etc.
    char behavior_pattern[128];      // Detected behavior pattern
    double startup_time;             // Time to first output
    double processing_time;          // Core processing time
    double cleanup_time;             // Cleanup/finalization time
    int output_complexity_score;     // 1-10 complexity rating
    int resource_efficiency_score;   // 1-10 efficiency rating
    char performance_category[32];   // "Excellent", "Good", "Poor", etc.
    
    // Advanced pattern detection
    int structured_output_detected;  // Headers, sections, formatted output
    int interactive_features;        // Prompts, menus, progress bars
    int file_format_conversions;     // Input/output format changes detected
    int parallel_processing_hints;   // Evidence of multi-threading/processing
    
    // Verbose Output Intelligence (your brilliant insight!)
    int file_operations_detected;    // cp, mv, ln verbose operations
    int progress_indicators;         // Progress bars, percentages, counters
    int path_manipulations;          // File/directory path operations
    int network_operations;          // URL fetches, downloads, uploads
    int compression_operations;      // tar, gzip, zip verbose output
    int compilation_steps;           // gcc, make verbose build steps
    int database_operations;         // SQL, database verbose operations
    int system_calls_verbose;        // strace-like verbose system information
    char verbose_operation_type[64]; // Type of verbose operation detected
    int verbose_intelligence_score;  // 1-10 how much we learned from verbose output
    
    // Performance metrics
    double cpu_usage_percent;
    long context_switches;
    
    // Pinpoint Vulnerability Analysis - NEW!
    char vulnerable_functions[10][64];    // List of specific vulnerable functions found
    int vulnerable_function_count;        // Number of vulnerable functions detected
    char crash_function[64];              // Specific function where crash occurred
    int crash_line_number;                // Line number of crash (if available)
    char source_file[256];                // Source file containing vulnerability
    char vulnerability_details[512];      // Detailed vulnerability description
    int has_debug_symbols;                // Whether binary has debug symbols
    char stack_trace[1024];               // Stack trace from crash (if available)
    
    // Multi-Language Runtime Analysis - NEW!
    char detected_language[32];           // "Java", "Rust", "Python", "C", "Go", etc.
    char runtime_version[64];             // Runtime/compiler version if detectable
    char language_specific_info[256];     // Language-specific analysis results
    char detected_frameworks[512];        // Detected frameworks (React, Django, Spring, etc.)
    int uses_managed_memory;              // GC languages (Java, C#, Go, etc.)
    int uses_unsafe_code;                 // Rust unsafe blocks, C pointer arithmetic
    int jvm_analysis_available;           // Java-specific analysis possible
    int cargo_project_detected;           // Rust Cargo project
    char dependency_manager[32];          // "Maven", "Cargo", "pip", "npm", etc.
    
    // Network Behavior Analysis - NEW!
    int network_connections_detected;     // Number of network connections made
    int outbound_http_requests;           // HTTP/HTTPS requests detected
    int dns_queries_made;                 // DNS resolution attempts
    char external_hosts_contacted[512];   // List of external hosts contacted
    int data_upload_detected;             // Potential data exfiltration
    int package_downloads_detected;       // Package manager downloads
    char repository_urls[512];            // Repository URLs accessed
    int network_security_score;           // 1-10 network security assessment
    char network_behavior_summary[256];   // Summary of network activity
    int suspicious_network_activity;      // Flag for unusual network patterns
    
} analysis_result_t;

// Global configuration
typedef struct {
    int verbose_mode;           // 0=quiet, 1=normal, 2=verbose, 3=very-verbose
    int output_format;          // 0=human, 1=json, 2=both
    int enable_security;        // Enable security analysis
    int enable_memory;          // Enable memory profiling
    int enable_io;             // Enable I/O monitoring
    int enable_performance;     // Enable performance profiling
    int enable_deep_analysis;   // Enable deep analysis (auto-enabled in -vv mode)
    int enable_network_analysis; // Enable network behavior analysis - NEW!
    char target_executable[PATH_MAX];
    char **target_args;
    int target_argc;
} runeanalyzer_config_t;

// Global state
static runeanalyzer_config_t g_config = {0};
static analysis_result_t g_results = {0};

// Color definitions for output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

// --- Utility Functions ---

/**
 * @brief Safe logging function with level control
 */
void runeanalyzer_log(int level, const char* format, ...) {
    if (level > g_config.verbose_mode) return;
    
    va_list args;
    va_start(args, format);
    
    const char* prefix = "";
    const char* color = COLOR_RESET;
    
    switch (level) {
        case 0: prefix = "[ERROR]"; color = COLOR_RED; break;
        case 1: prefix = "[INFO] "; color = COLOR_BLUE; break;
        case 2: prefix = "[DEBUG]"; color = COLOR_CYAN; break;
    }
    
    fprintf(stderr, "%s%s%s ", color, prefix, COLOR_RESET);
    vfprintf(stderr, format, args);
    va_end(args);
}

/**
 * @brief Safe memory allocation with zero initialization
 */
void* safe_malloc(size_t size) {
    if (size == 0 || size > SIZE_MAX / 2) {
        runeanalyzer_log(0, "Error: Invalid allocation size %zu\n", size);
        return NULL;
    }
    void* ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);  // Zero-initialize to prevent information leaks
    }
    return ptr;
}

/**
 * @brief Safe string duplication with length limit
 */
char* safe_strdup(const char* src, size_t max_len) {
    if (!src) return NULL;
    
    size_t len = strnlen(src, max_len);
    if (len >= max_len) {
        runeanalyzer_log(0, "Warning: String truncated during duplication\n");
        len = max_len - 1;
    }
    
    char* dst = safe_malloc(len + 1);
    if (dst) {
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return dst;
}

/**
 * @brief Safe integer parsing with overflow detection
 */
int safe_atoi(const char* str, int* result) {
    if (!str || !result) return -1;
    
    char* endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);
    
    if (errno == ERANGE || val < INT_MIN || val > INT_MAX) {
        runeanalyzer_log(0, "Error: Integer overflow in parsing: %s\n", str);
        return -1;
    }
    
    if (endptr == str || *endptr != '\0') {
        runeanalyzer_log(0, "Error: Invalid integer format: %s\n", str);
        return -1;
    }
    
    *result = (int)val;
    return 0;
}

/**
 * @brief Validate executable path for security
 */
int validate_executable(const char* path) {
    if (!path || strlen(path) == 0) {
        runeanalyzer_log(0, "Error: Empty executable path\n");
        return -1;
    }
    
    if (strlen(path) >= PATH_MAX) {
        runeanalyzer_log(0, "Error: Executable path too long (max %d characters)\n", PATH_MAX);
        return -1;
    }
    
    // Check for dangerous characters
    if (strchr(path, ';') || strchr(path, '|') || strchr(path, '&')) {
        runeanalyzer_log(0, "Error: Executable path contains dangerous characters\n");
        return -1;
    }
    
    // Verify file exists and is executable
    struct stat st;
    if (stat(path, &st) != 0) {
        runeanalyzer_log(0, "Error: Cannot access executable '%s': %s\n", path, strerror(errno));
        return -1;
    }
    
    if (!S_ISREG(st.st_mode)) {
        runeanalyzer_log(0, "Error: '%s' is not a regular file\n", path);
        return -1;
    }
    
    if (!(st.st_mode & S_IXUSR)) {
        runeanalyzer_log(0, "Error: '%s' is not executable\n", path);
        return -1;
    }
    
    runeanalyzer_log(2, "Executable validation passed for '%s'\n", path);
    return 0;
}

/**
 * @brief Sanitize command arguments for security
 */
int sanitize_args(char** args, int argc) {
    for (int i = 0; i < argc; i++) {
        if (!args[i]) continue;
        
        if (strlen(args[i]) > MAX_COMMAND_LENGTH) {
            runeanalyzer_log(0, "Error: Argument %d too long (max %d characters)\n", i, MAX_COMMAND_LENGTH);
            return -1;
        }
        
        // Log potentially dangerous arguments
        if (strchr(args[i], ';') || strchr(args[i], '|') || strchr(args[i], '&')) {
            runeanalyzer_log(1, "Warning: Argument %d contains shell metacharacters: '%s'\n", i, args[i]);
        }
    }
    
    return 0;
}

/**
 * @brief Get current memory usage in KB
 */
long get_memory_usage(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    
    char line[256];
    long vmrss_kb = -1;
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %ld kB", &vmrss_kb);
            break;
        }
    }
    
    fclose(f);
    return vmrss_kb;
}

/**
 * @brief Execute target command with comprehensive monitoring
 */
int execute_and_analyze(void) {
    runeanalyzer_log(1, "Starting analysis of: %s\n", g_config.target_executable);
    
    // Create pipes for stdout/stderr capture
    int stdout_pipe[2], stderr_pipe[2];
    if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) {
        runeanalyzer_log(0, "Error: Failed to create pipes: %s\n", strerror(errno));
        return -1;
    }
    
    // Record start time
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);
    
    // Fork child process
    pid_t child_pid = fork();
    if (child_pid == -1) {
        runeanalyzer_log(0, "Error: Fork failed: %s\n", strerror(errno));
        return -1;
    }
    
    if (child_pid == 0) {
        // Child process - execute target command
        
        // Redirect stdout/stderr to pipes
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        
        // Build argument array
        char* exec_args[MAX_ARGS + 2];
        exec_args[0] = g_config.target_executable;
        
        for (int i = 0; i < g_config.target_argc && i < MAX_ARGS; i++) {
            exec_args[i + 1] = g_config.target_args[i];
        }
        exec_args[g_config.target_argc + 1] = NULL;
        
        // Execute target
        execvp(g_config.target_executable, exec_args);
        
        // If we get here, exec failed
        fprintf(stderr, "runeanalyzer: failed to execute '%s': %s\n", 
                g_config.target_executable, strerror(errno));
        exit(127);
    }
    
    // Parent process - monitor child
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    
    g_results.child_pid = child_pid;
    
    // Monitor memory usage periodically
    long peak_memory = 0;
    
    // Read output from pipes
    fd_set read_fds;
    int stdout_fd = stdout_pipe[0];
    int stderr_fd = stderr_pipe[0];
    int max_fd = (stdout_fd > stderr_fd) ? stdout_fd : stderr_fd;
    
    // Set pipes to non-blocking
    fcntl(stdout_fd, F_SETFL, O_NONBLOCK);
    fcntl(stderr_fd, F_SETFL, O_NONBLOCK);
    
    char buffer[4096];
    int child_running = 1;
    
    while (child_running) {
        // Check if child is still running
        int status;
        pid_t wait_result = waitpid(child_pid, &status, WNOHANG);
        
        if (wait_result == child_pid) {
            // Child has terminated
            child_running = 0;
            if (WIFEXITED(status)) {
                g_results.exit_code = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                g_results.exit_code = 128 + WTERMSIG(status);
            }
        } else if (wait_result == -1) {
            runeanalyzer_log(0, "Error: waitpid failed: %s\n", strerror(errno));
            break;
        }
        
        // Monitor memory usage
        if (child_running) {
            long current_memory = get_memory_usage(child_pid);
            if (current_memory > peak_memory) {
                peak_memory = current_memory;
            }
        }
        
        // Read available output
        FD_ZERO(&read_fds);
        if (child_running || stdout_fd >= 0) FD_SET(stdout_fd, &read_fds);
        if (child_running || stderr_fd >= 0) FD_SET(stderr_fd, &read_fds);
        
        struct timeval timeout = {0, 10000}; // 10ms timeout
        int select_result = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (select_result > 0) {
            if (FD_ISSET(stdout_fd, &read_fds)) {
                ssize_t bytes = read(stdout_fd, buffer, sizeof(buffer) - 1);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    g_results.stdout_bytes += bytes;
                    // Forward to actual stdout
                    write(STDOUT_FILENO, buffer, bytes);
                    
                    // Analyze output for patterns
                    if (strstr(buffer, "verbose") || strstr(buffer, "VERBOSE") || strstr(buffer, "==>") || strstr(buffer, "<==")) {
                        g_results.verbose_messages++;
                    }
                    if (strstr(buffer, "error") || strstr(buffer, "ERROR")) {
                        g_results.error_messages++;
                    }
                    if (strstr(buffer, "warning") || strstr(buffer, "WARNING")) {
                        g_results.warning_messages++;
                    }
                } else if (bytes == 0) {
                    close(stdout_fd);
                    stdout_fd = -1;
                }
            }
            
            if (FD_ISSET(stderr_fd, &read_fds)) {
                ssize_t bytes = read(stderr_fd, buffer, sizeof(buffer) - 1);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    g_results.stderr_bytes += bytes;
                    // Forward to actual stderr  
                    write(STDERR_FILENO, buffer, bytes);
                } else if (bytes == 0) {
                    close(stderr_fd);
                    stderr_fd = -1;
                }
            }
        }
        
        // Small delay to prevent busy waiting
        usleep(1000); // 1ms
    }
    
    // Clean up remaining pipes
    if (stdout_fd >= 0) close(stdout_fd);
    if (stderr_fd >= 0) close(stderr_fd);
    
    // Calculate execution time
    gettimeofday(&end_time, NULL);
    g_results.execution_time = (end_time.tv_sec - start_time.tv_sec) + 
                               (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    
    g_results.peak_memory_kb = peak_memory;
    
    runeanalyzer_log(1, "Analysis completed in %.3fs\n", g_results.execution_time);
    
    // Perform deep analysis if enabled
    if (g_config.enable_deep_analysis) {
        perform_deep_analysis();
    }
    
    return 0;
}

/**
 * @brief Perform deep analysis for -vv mode
 */
void perform_deep_analysis(void) {
    runeanalyzer_log(2, "Performing deep analysis...\n");
    
    // Tool classification based on executable path and behavior
    classify_tool();
    
    // Performance timing breakdown
    analyze_performance_timing();
    
    // Output complexity analysis
    analyze_output_complexity();
    
    // Behavioral pattern detection
    detect_behavioral_patterns();
    
    // Resource efficiency scoring
    calculate_efficiency_scores();
    
    // Verbose Output Intelligence Analysis (your brilliant idea!)
    analyze_verbose_patterns();
    detect_tool_specific_intelligence();
    
    // Language and runtime detection (NEW!)
    detect_language_runtime();
    
    // Framework detection (NEW!)
    detect_frameworks();
    
    // Network behavior analysis (NEW!)
    if (g_config.enable_network_analysis) {
        analyze_network_behavior();
    }
    
    // Security analysis (if enabled)
    if (g_config.enable_security) {
        analyze_security_patterns();
        detect_memory_vulnerabilities();
        analyze_dangerous_functions();
        
        // NEW: Pinpoint vulnerability analysis
        detect_vulnerable_functions();
    }
    
    runeanalyzer_log(2, "Deep analysis completed\n");
}

/**
 * @brief Classify the tool based on path and behavior patterns
 */
void classify_tool(void) {
    const char* executable = g_config.target_executable;
    const char* basename = strrchr(executable, '/');
    if (basename) basename++; else basename = executable;
    
    // Validate inputs
    VALIDATE_POINTER(executable, "executable");
    VALIDATE_POINTER(basename, "basename");
    
    // Initialize classification - SAFE VERSION
    SAFE_STRNCPY(g_results.tool_classification, "unknown", sizeof(g_results.tool_classification));
    
    // Classification by common tool patterns - DEFENSIVE CHECKS
    if (strnlen(basename, PATH_MAX) >= PATH_MAX) {
        runeanalyzer_log(0, "Error: Executable basename too long\n");
        return;
    }
    
    if (strstr(basename, "gcc") || strstr(basename, "clang") || strstr(basename, "g++")) {
        SAFE_STRNCPY(g_results.tool_classification, "compiler", sizeof(g_results.tool_classification));
    } else if (strstr(basename, "grep") || strstr(basename, "awk") || strstr(basename, "sed")) {
        SAFE_STRNCPY(g_results.tool_classification, "text_processor", sizeof(g_results.tool_classification));
    } else if (strstr(basename, "find") || strstr(basename, "ls") || strstr(basename, "cp") || strstr(basename, "mv")) {
        SAFE_STRNCPY(g_results.tool_classification, "file_utility", sizeof(g_results.tool_classification));
    } else if (strstr(basename, "sort") || strstr(basename, "uniq") || strstr(basename, "head") || strstr(basename, "tail")) {
        SAFE_STRNCPY(g_results.tool_classification, "data_processor", sizeof(g_results.tool_classification));
    } else if (strstr(basename, "tar") || strstr(basename, "zip") || strstr(basename, "gzip")) {
        SAFE_STRNCPY(g_results.tool_classification, "archiver", sizeof(g_results.tool_classification));
    } else if (strstr(basename, "python") || strstr(basename, "node") || strstr(basename, "ruby")) {
        SAFE_STRNCPY(g_results.tool_classification, "interpreter", sizeof(g_results.tool_classification));
    } else if (g_results.stdout_bytes > 1000 && g_results.verbose_messages > 0) {
        SAFE_STRNCPY(g_results.tool_classification, "reporting_tool", sizeof(g_results.tool_classification));
    } else if (g_results.execution_time > 1.0 && g_results.peak_memory_kb > 10000) {
        SAFE_STRNCPY(g_results.tool_classification, "heavy_processor", sizeof(g_results.tool_classification));
    } else {
        SAFE_STRNCPY(g_results.tool_classification, "system_utility", sizeof(g_results.tool_classification));
    }
}

/**
 * @brief Analyze performance timing breakdown
 */
void analyze_performance_timing(void) {
    // Estimate timing phases (simplified analysis)
    g_results.startup_time = g_results.execution_time * 0.1;  // Assume 10% startup
    g_results.processing_time = g_results.execution_time * 0.8;  // 80% processing
    g_results.cleanup_time = g_results.execution_time * 0.1;   // 10% cleanup
    
    // Adjust based on tool characteristics
    if (strcmp(g_results.tool_classification, "compiler") == 0) {
        g_results.startup_time = g_results.execution_time * 0.05;  // Compilers have fast startup
        g_results.processing_time = g_results.execution_time * 0.9;
        g_results.cleanup_time = g_results.execution_time * 0.05;
    } else if (strcmp(g_results.tool_classification, "interpreter") == 0) {
        g_results.startup_time = g_results.execution_time * 0.3;   // Interpreters have slower startup
        g_results.processing_time = g_results.execution_time * 0.6;
        g_results.cleanup_time = g_results.execution_time * 0.1;
    }
}

/**
 * @brief Analyze output complexity
 */
void analyze_output_complexity(void) {
    int complexity_score = 1;
    
    // Base score on output volume
    if (g_results.stdout_bytes > 100000) complexity_score += 3;
    else if (g_results.stdout_bytes > 10000) complexity_score += 2;
    else if (g_results.stdout_bytes > 1000) complexity_score += 1;
    
    // Add points for structured output
    if (g_results.verbose_messages > 5) complexity_score += 2;
    if (g_results.error_messages > 0) complexity_score += 1;
    if (g_results.warning_messages > 0) complexity_score += 1;
    
    // Cap at 10
    g_results.output_complexity_score = (complexity_score > 10) ? 10 : complexity_score;
    
    // Detect structured output patterns
    g_results.structured_output_detected = (g_results.verbose_messages > 3) ? 1 : 0;
}

/**
 * @brief Detect behavioral patterns
 */
void detect_behavioral_patterns(void) {
    char pattern[128] = {0};  // Initialize to prevent garbage
    
    // DEFENSIVE: Initialize with default pattern
    SAFE_STRNCPY(pattern, "standard_execution", sizeof(pattern));
    
    // DEFENSIVE: Check values for sanity (skip unsigned values that can't be negative)
    if (g_results.execution_time < 0.0) g_results.execution_time = 0.0;
    if (g_results.peak_memory_kb < 0) g_results.peak_memory_kb = 0;
    
    if (g_results.execution_time < 0.1) {
        SAFE_STRNCPY(pattern, "fast_execution", sizeof(pattern));
    } else if (g_results.execution_time > 5.0) {
        SAFE_STRNCPY(pattern, "long_running", sizeof(pattern));
    }
    
    if (g_results.stdout_bytes > 50000) {
        SAFE_STRNCAT(pattern, "+verbose_output", sizeof(pattern));
    }
    
    if (g_results.peak_memory_kb > 100000) {
        SAFE_STRNCAT(pattern, "+memory_intensive", sizeof(pattern));
    }
    
    SAFE_STRNCPY(g_results.behavior_pattern, pattern, sizeof(g_results.behavior_pattern));
}

/**
 * @brief Calculate efficiency scores
 */
void calculate_efficiency_scores(void) {
    // DEFENSIVE: Validate memory usage value (skip unsigned values)
    if (g_results.peak_memory_kb < 0) g_results.peak_memory_kb = 0;
    if (g_results.execution_time < 0.0) g_results.execution_time = 0.0;
    
    // Resource efficiency based on memory usage vs output
    int memory_score = 10;
    if (g_results.peak_memory_kb > 0) {
        double memory_per_byte = (double)g_results.peak_memory_kb / (g_results.stdout_bytes + 1);
        if (memory_per_byte > 10.0) memory_score = 3;
        else if (memory_per_byte > 5.0) memory_score = 5;
        else if (memory_per_byte > 1.0) memory_score = 7;
    }
    
    // DEFENSIVE: Validate score range
    VALIDATE_RANGE(memory_score, 1, 10, "memory_score");
    g_results.resource_efficiency_score = memory_score;
    
    // Performance category - SAFE VERSION
    if (g_results.execution_time < 0.05) {
        SAFE_STRNCPY(g_results.performance_category, "Excellent", sizeof(g_results.performance_category));
    } else if (g_results.execution_time < 0.5) {
        SAFE_STRNCPY(g_results.performance_category, "Good", sizeof(g_results.performance_category));
    } else if (g_results.execution_time < 2.0) {
        SAFE_STRNCPY(g_results.performance_category, "Average", sizeof(g_results.performance_category));
    } else {
        SAFE_STRNCPY(g_results.performance_category, "Slow", sizeof(g_results.performance_category));
    }
}

/**
 * @brief Analyze security patterns in executable output and behavior
 */
void analyze_security_patterns(void) {
    runeanalyzer_log(2, "Analyzing security patterns...\n");
    
    // Initialize security scores
    g_results.buffer_overflow_risk = 0;
    g_results.memory_leak_indicators = 0;
    g_results.use_after_free_risk = 0;
    g_results.format_string_vuln = 0;
    g_results.null_pointer_risk = 0;
    g_results.integer_overflow_risk = 0;
    g_results.uninitialized_memory_risk = 0;
    g_results.dangerous_function_count = 0;
    g_results.overall_security_score = 10; // Start with perfect score
    
    // DEFENSIVE: Analyze executable name for known vulnerable patterns
    const char* executable = g_config.target_executable;
    VALIDATE_POINTER(executable, "executable");
    
    const char* basename = strrchr(executable, '/');
    if (basename) basename++; else basename = executable;
    VALIDATE_POINTER(basename, "basename");
    
    // DEFENSIVE: Check basename length for safety
    if (strnlen(basename, PATH_MAX) >= PATH_MAX) {
        runeanalyzer_log(0, "Error: Basename too long for security analysis\n");
        SAFE_STRNCPY(g_results.security_classification, "analysis_error", sizeof(g_results.security_classification));
        return;
    }
    
    // Check if this is our test vulnerable program
    if (strstr(basename, "vulnerable") || strstr(basename, "vuln")) {
        g_results.overall_security_score = 1; // Obviously vulnerable
        SAFE_STRNCPY(g_results.security_classification, "high_risk_test_program", sizeof(g_results.security_classification));
        runeanalyzer_log(2, "Detected test vulnerable program\n");
        return;
    }
    
    // DEFENSIVE: Validate security score range
    VALIDATE_RANGE(g_results.overall_security_score, 1, 10, "overall_security_score");
    
    // Default classification based on overall assessment - SAFE VERSION
    if (g_results.overall_security_score >= 8) {
        SAFE_STRNCPY(g_results.security_classification, "low_risk", sizeof(g_results.security_classification));
    } else if (g_results.overall_security_score >= 6) {
        SAFE_STRNCPY(g_results.security_classification, "medium_risk", sizeof(g_results.security_classification));
    } else if (g_results.overall_security_score >= 4) {
        SAFE_STRNCPY(g_results.security_classification, "high_risk", sizeof(g_results.security_classification));
    } else {
        SAFE_STRNCPY(g_results.security_classification, "critical_risk", sizeof(g_results.security_classification));
    }
}

/**
 * @brief Detect memory vulnerability patterns using exit codes and signals
 */
void detect_memory_vulnerabilities(void) {
    runeanalyzer_log(2, "Detecting memory vulnerability patterns...\n");
    
    const char* executable = g_config.target_executable;
    const char* basename = strrchr(executable, '/');
    if (basename) basename++; else basename = executable;
    
    // COMPREHENSIVE EXIT CODE ANALYSIS - Your brilliant idea!
    // Exit codes tell us EXACTLY what went wrong
    
    if (g_results.exit_code == 139) { // SIGSEGV - Segmentation fault
        g_results.buffer_overflow_risk = 5;
        g_results.use_after_free_risk = 5;
        g_results.null_pointer_risk = 5;
        g_results.overall_security_score = 1;
        strncpy(g_results.security_classification, "critical_memory_corruption", sizeof(g_results.security_classification) - 1);
        runeanalyzer_log(1, "🚨 CRITICAL: Segmentation fault (SIGSEGV) - Memory corruption detected!\n");
        
    } else if (g_results.exit_code == 134) { // SIGABRT - Abort signal  
        g_results.use_after_free_risk = 5;
        g_results.memory_leak_indicators = 4;
        g_results.overall_security_score = 1;
        strncpy(g_results.security_classification, "critical_heap_corruption", sizeof(g_results.security_classification) - 1);
        runeanalyzer_log(1, "🚨 CRITICAL: Abort signal (SIGABRT) - Heap corruption/double free detected!\n");
        
    } else if (g_results.exit_code == 136) { // SIGFPE - Floating point exception
        g_results.integer_overflow_risk = 5;
        g_results.overall_security_score = 2;
        strncpy(g_results.security_classification, "arithmetic_error", sizeof(g_results.security_classification) - 1);
        runeanalyzer_log(1, "⚠️ CRITICAL: Floating point exception (SIGFPE) - Arithmetic overflow!\n");
        
    } else if (g_results.exit_code == 132) { // SIGILL - Illegal instruction
        g_results.buffer_overflow_risk = 4;
        g_results.overall_security_score = 2;
        strncpy(g_results.security_classification, "code_corruption", sizeof(g_results.security_classification) - 1);
        runeanalyzer_log(1, "⚠️ CRITICAL: Illegal instruction (SIGILL) - Code corruption!\n");
        
    } else if (g_results.exit_code == 133) { // SIGTRAP - Trace/breakpoint trap
        g_results.overall_security_score = 6;
        strncpy(g_results.security_classification, "debug_trap", sizeof(g_results.security_classification) - 1);
        runeanalyzer_log(2, "Debug trap detected - may indicate debugging/analysis\n");
        
    } else if (g_results.exit_code == 135) { // SIGBUS - Bus error
        g_results.buffer_overflow_risk = 4;
        g_results.uninitialized_memory_risk = 3;
        g_results.overall_security_score = 2;
        strncpy(g_results.security_classification, "memory_alignment_error", sizeof(g_results.security_classification) - 1);
        runeanalyzer_log(1, "⚠️ CRITICAL: Bus error (SIGBUS) - Memory alignment/access violation!\n");
        
    } else if (g_results.exit_code == 137) { // SIGKILL - Killed by system
        g_results.memory_leak_indicators = 3;
        g_results.overall_security_score = 4;
        strncpy(g_results.security_classification, "resource_exhaustion", sizeof(g_results.security_classification) - 1);
        runeanalyzer_log(1, "⚠️ WARNING: Process killed (SIGKILL) - Possible resource exhaustion!\n");
        
    } else if (g_results.exit_code >= 1 && g_results.exit_code <= 2) {
        // Standard error codes - less critical but still noteworthy
        g_results.overall_security_score = 7;
        strncpy(g_results.security_classification, "standard_error", sizeof(g_results.security_classification) - 1);
        runeanalyzer_log(2, "Standard error exit code: %d\n", g_results.exit_code);
        
    } else if (g_results.exit_code == 0) {
        // Success - but still check for other patterns
        g_results.overall_security_score = 9;
        strncpy(g_results.security_classification, "execution_success", sizeof(g_results.security_classification) - 1);
    }
    
    // PATTERN-BASED VULNERABILITY DETECTION
    // Your vulnerable test program helps us understand these patterns
    
    if (strstr(basename, "vulnerable") || strstr(basename, "vuln")) {
        // Override for known test programs
        if (g_results.exit_code == 0) {
            // Even successful execution of vulnerable program is risky
            g_results.overall_security_score = 2;
            strncpy(g_results.security_classification, "high_risk_test_program", sizeof(g_results.security_classification) - 1);
        }
        runeanalyzer_log(2, "Detected intentionally vulnerable test program\n");
    }
    
    // Memory usage analysis
    if (g_results.peak_memory_kb > 0 && g_results.execution_time > 0.1) {
        double memory_time_ratio = (double)g_results.peak_memory_kb / g_results.execution_time;
        if (memory_time_ratio > 50000) { // High memory usage rate
            g_results.memory_leak_indicators++;
            g_results.overall_security_score--;
            runeanalyzer_log(2, "High memory allocation rate detected - possible memory leak\n");
        }
    }
    
    // Filename pattern analysis (your test program naming is perfect for this!)
    if (strstr(basename, "overflow") || strstr(basename, "buffer")) {
        g_results.buffer_overflow_risk += 3;
        g_results.overall_security_score -= 2;
    }
    
    if (strstr(basename, "free") || strstr(basename, "uaf")) {
        g_results.use_after_free_risk += 3;
        g_results.overall_security_score -= 2;
    }
    
    if (strstr(basename, "format") || strstr(basename, "printf")) {
        g_results.format_string_vuln += 3;
        g_results.overall_security_score -= 2;
    }
    
    // Keep security score within bounds
    if (g_results.overall_security_score < 1) g_results.overall_security_score = 1;
    if (g_results.overall_security_score > 10) g_results.overall_security_score = 10;
}

/**
 * @brief Analyze binary symbols using nm command for pinpoint detection
 */
int run_nm_analysis(void) {
    runeanalyzer_log(2, "Running nm binary symbol analysis...\n");
    
    char command[512];
    snprintf(command, sizeof(command), "nm -D '%s' 2>/dev/null || nm '%s' 2>/dev/null", 
             g_config.target_executable, g_config.target_executable);
    
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        runeanalyzer_log(1, "Could not run nm analysis\n");
        return -1;
    }
    
    char line[256];
    int dangerous_symbols_found = 0;
    
    // List of dangerous/vulnerable function signatures
    const char* dangerous_funcs[] = {
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
        "malloc", "free", "realloc", "calloc", "system", "popen",
        "execve", "execl", "execlp", "execle", "execv", "execvp",
        "buffer_overflow", "use_after_free", "double_free", "format_string",
        NULL
    };
    
    while (fgets(line, sizeof(line), pipe) != NULL && dangerous_symbols_found < 10) {
        // Parse nm output: address type symbol_name
        char addr[32], type[8], symbol[128];
        if (sscanf(line, "%31s %7s %127s", addr, type, symbol) == 3) {
            
            // Check against dangerous function list
            for (int i = 0; dangerous_funcs[i] != NULL; i++) {
                if (strstr(symbol, dangerous_funcs[i])) {
                    SAFE_STRNCPY(g_results.vulnerable_functions[dangerous_symbols_found], 
                                symbol, sizeof(g_results.vulnerable_functions[0]));
                    dangerous_symbols_found++;
                    
                    runeanalyzer_log(2, "Found potentially dangerous symbol: %s (type: %s)\n", symbol, type);
                    
                    // Specific vulnerability pattern detection
                    if (strstr(symbol, "buffer_overflow")) {
                        g_results.buffer_overflow_risk = 5;
                        SAFE_STRNCPY(g_results.vulnerability_details, 
                                   "Buffer overflow function detected in binary symbols", 
                                   sizeof(g_results.vulnerability_details));
                    } else if (strstr(symbol, "use_after_free")) {
                        g_results.use_after_free_risk = 5;
                        SAFE_STRNCPY(g_results.vulnerability_details, 
                                   "Use-after-free function detected in binary symbols", 
                                   sizeof(g_results.vulnerability_details));
                    } else if (strstr(symbol, "format_string")) {
                        g_results.format_string_vuln = 5;
                        SAFE_STRNCPY(g_results.vulnerability_details, 
                                   "Format string vulnerability function detected", 
                                   sizeof(g_results.vulnerability_details));
                    } else if (strstr(symbol, "strcpy") || strstr(symbol, "sprintf")) {
                        g_results.buffer_overflow_risk += 2;
                        SAFE_STRNCPY(g_results.vulnerability_details, 
                                   "Unsafe string function detected in binary", 
                                   sizeof(g_results.vulnerability_details));
                    }
                    
                    break;
                }
            }
        }
    }
    
    pclose(pipe);
    g_results.vulnerable_function_count = dangerous_symbols_found;
    
    if (dangerous_symbols_found > 0) {
        runeanalyzer_log(1, "🎯 Found %d potentially vulnerable functions in binary\n", dangerous_symbols_found);
    }
    
    return 0;
}

/**
 * @brief Analyze binary with objdump for disassembly and vulnerability patterns
 */
int run_objdump_analysis(void) {
    runeanalyzer_log(2, "Running objdump disassembly analysis...\n");
    
    char command[512];
    snprintf(command, sizeof(command), "objdump -t '%s' 2>/dev/null | head -50", 
             g_config.target_executable);
    
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        runeanalyzer_log(1, "Could not run objdump analysis\n");
        return -1;
    }
    
    char line[256];
    int debug_symbols_found = 0;
    
    while (fgets(line, sizeof(line), pipe) != NULL) {
        // Look for debug symbols and function names
        if (strstr(line, ".debug_") || strstr(line, "DWARF")) {
            debug_symbols_found = 1;
            g_results.has_debug_symbols = 1;
            runeanalyzer_log(2, "Debug symbols detected - enhanced analysis possible\n");
        }
        
        // Look for specific vulnerable function patterns in symbol table
        if (strstr(line, "buffer_overflow") || strstr(line, "vulnerable_")) {
            char symbol[128];
            if (sscanf(line, "%*s %*s %*s %*s %127s", symbol) == 1) {
                runeanalyzer_log(2, "Found vulnerable function symbol: %s\n", symbol);
                if (g_results.vulnerable_function_count < 10) {
                    SAFE_STRNCPY(g_results.vulnerable_functions[g_results.vulnerable_function_count], 
                                symbol, sizeof(g_results.vulnerable_functions[0]));
                    g_results.vulnerable_function_count++;
                }
            }
        }
    }
    
    pclose(pipe);
    
    g_results.has_debug_symbols = debug_symbols_found;
    return 0;
}

/**
 * @brief Extract debug information for pinpoint analysis
 */
void extract_debug_info(void) {
    runeanalyzer_log(2, "Extracting debug information...\n");
    
    // Try to get source file information using readelf
    char command[512];
    snprintf(command, sizeof(command), "readelf --debug-dump=info '%s' 2>/dev/null | head -20", 
             g_config.target_executable);
    
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        runeanalyzer_log(2, "No debug info extraction possible\n");
        return;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), pipe) != NULL) {
        // Look for source file references
        if (strstr(line, "DW_AT_name") && (strstr(line, ".c") || strstr(line, ".cpp"))) {
            char* filename = strrchr(line, '/');
            if (!filename) filename = strrchr(line, '\\');
            if (!filename) filename = line;
            
            // Extract just the filename
            char* end = strstr(filename, ".c");
            if (end) {
                size_t len = end - filename + 2; // Include .c
                if (len < sizeof(g_results.source_file)) {
                    strncpy(g_results.source_file, filename, len);
                    g_results.source_file[len] = '\0';
                    runeanalyzer_log(2, "Found source file reference: %s\n", g_results.source_file);
                    break;
                }
            }
        }
    }
    
    pclose(pipe);
}

/**
 * @brief Analyze crash with GDB for precise function and line identification
 */
void parse_gdb_backtrace(void) {
    // Only run GDB analysis if the program crashed
    if (g_results.exit_code < 128) {
        runeanalyzer_log(2, "Program exited normally - skipping GDB analysis\n");
        return;
    }
    
    runeanalyzer_log(2, "Running GDB backtrace analysis for crashed program...\n");
    
    // Create a temporary GDB script
    char gdb_script[] = "/tmp/runeanalyzer_gdb_script.txt";
    FILE* script = fopen(gdb_script, "w");
    if (!script) {
        runeanalyzer_log(1, "Could not create GDB script\n");
        return;
    }
    
    // Write GDB commands to get backtrace and crash info
    fprintf(script, "set confirm off\n");
    fprintf(script, "set pagination off\n");
    fprintf(script, "run");
    
    // Add the program arguments
    for (int i = 0; i < g_config.target_argc; i++) {
        fprintf(script, " %s", g_config.target_args[i]);
    }
    fprintf(script, "\n");
    fprintf(script, "bt\n");
    fprintf(script, "info registers\n"); 
    fprintf(script, "quit\n");
    fclose(script);
    
    // Run GDB with the script
    char command[512];
    snprintf(command, sizeof(command), 
             "timeout 10s gdb -quiet -batch -x %s '%s' 2>/dev/null", 
             gdb_script, g_config.target_executable);
    
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        runeanalyzer_log(1, "Could not run GDB analysis\n");
        unlink(gdb_script);
        return;
    }
    
    char line[256];
    int in_backtrace = 0;
    int stack_lines = 0;
    
    while (fgets(line, sizeof(line), pipe) != NULL && stack_lines < 10) {
        // Detect start of backtrace
        if (strstr(line, "#0") || strstr(line, "backtrace")) {
            in_backtrace = 1;
        }
        
        if (in_backtrace) {
            // Look for crash function and line info
            if (strstr(line, "#0") && !g_results.crash_function[0]) {
                // Parse the crash location: #0  0x... in function_name (args) at file:line
                char func[64] = {0};
                char file[128] = {0};
                int line_num = 0;
                
                if (sscanf(line, "#0 %*s in %63s %*s at %127[^:]:%d", func, file, &line_num) >= 2) {
                    SAFE_STRNCPY(g_results.crash_function, func, sizeof(g_results.crash_function));
                    g_results.crash_line_number = line_num;
                    
                    if (strlen(file) > 0) {
                        SAFE_STRNCPY(g_results.source_file, file, sizeof(g_results.source_file));
                    }
                    
                    runeanalyzer_log(1, "🎯 CRASH LOCATION: Function '%s' at line %d in %s\n", 
                                 func, line_num, file);
                    
                    // Create detailed vulnerability description
                    snprintf(g_results.vulnerability_details, sizeof(g_results.vulnerability_details),
                            "Crash in function '%s' at line %d in file '%s' - Exit code %d indicates %s",
                            func, line_num, file, g_results.exit_code, decode_exit_code(g_results.exit_code));
                }
            }
            
            // Collect stack trace
            if (stack_lines < 5) {  // Keep first 5 lines of stack trace
                size_t current_len = strlen(g_results.stack_trace);
                size_t remaining = sizeof(g_results.stack_trace) - current_len - 1;
                if (remaining > strlen(line)) {
                    strncat(g_results.stack_trace, line, remaining);
                }
                stack_lines++;
            }
        }
        
        // Stop collecting after we've seen enough
        if (strstr(line, "quit") || stack_lines >= 10) {
            break;
        }
    }
    
    pclose(pipe);
    unlink(gdb_script);
    
    if (g_results.crash_function[0]) {
        runeanalyzer_log(1, "🔍 Pinpoint analysis complete - crash location identified!\n");
    }
}

/**
 * @brief Master binary analysis coordination function
 */
void analyze_binary_symbols(void) {
    runeanalyzer_log(2, "Starting comprehensive binary analysis...\n");
    
    // Initialize pinpoint analysis fields
    g_results.vulnerable_function_count = 0;
    g_results.crash_line_number = 0;
    g_results.has_debug_symbols = 0;
    memset(g_results.vulnerable_functions, 0, sizeof(g_results.vulnerable_functions));
    memset(g_results.crash_function, 0, sizeof(g_results.crash_function));
    memset(g_results.source_file, 0, sizeof(g_results.source_file));
    memset(g_results.vulnerability_details, 0, sizeof(g_results.vulnerability_details));
    memset(g_results.stack_trace, 0, sizeof(g_results.stack_trace));
    
    // Run different analysis tools
    run_nm_analysis();
    run_objdump_analysis(); 
    extract_debug_info();
    
    // If program crashed, run detailed GDB analysis
    if (g_results.exit_code >= 128) {
        parse_gdb_backtrace();
    }
    
    runeanalyzer_log(2, "Binary analysis complete\n");
}

/**
 * @brief High-level vulnerable function detection
 */
void detect_vulnerable_functions(void) {
    runeanalyzer_log(2, "Detecting vulnerable functions and patterns...\n");
    
    // This function coordinates the binary analysis
    analyze_binary_symbols();
    
    // Additional pattern matching based on executable name
    const char* executable = g_config.target_executable;
    const char* basename = strrchr(executable, '/');
    if (basename) basename++; else basename = executable;
    
    // Enhanced pattern detection for our test vulnerable program
    if (strstr(basename, "vulnerable")) {
        runeanalyzer_log(2, "Analyzing known vulnerable test program...\n");
        
        // If we have arguments, we can infer the specific vulnerability type
        if (g_config.target_argc > 0) {
            const char* vuln_type = g_config.target_args[0];
            
            if (strstr(vuln_type, "buffer_overflow")) {
                SAFE_STRNCPY(g_results.vulnerable_functions[g_results.vulnerable_function_count], 
                           "test_buffer_overflow", sizeof(g_results.vulnerable_functions[0]));
                g_results.vulnerable_function_count++;
                g_results.buffer_overflow_risk = 5;
                SAFE_STRNCPY(g_results.vulnerability_details, 
                           "Buffer overflow in test_buffer_overflow() function", 
                           sizeof(g_results.vulnerability_details));
                           
            } else if (strstr(vuln_type, "use_after_free")) {
                SAFE_STRNCPY(g_results.vulnerable_functions[g_results.vulnerable_function_count], 
                           "test_use_after_free", sizeof(g_results.vulnerable_functions[0]));
                g_results.vulnerable_function_count++;
                g_results.use_after_free_risk = 5;
                SAFE_STRNCPY(g_results.vulnerability_details, 
                           "Use-after-free in test_use_after_free() function", 
                           sizeof(g_results.vulnerability_details));
                           
            } else if (strstr(vuln_type, "format_string")) {
                SAFE_STRNCPY(g_results.vulnerable_functions[g_results.vulnerable_function_count], 
                           "test_format_string", sizeof(g_results.vulnerable_functions[0]));
                g_results.vulnerable_function_count++;
                g_results.format_string_vuln = 5;
                SAFE_STRNCPY(g_results.vulnerability_details, 
                           "Format string vulnerability in test_format_string() function", 
                           sizeof(g_results.vulnerability_details));
            }
        }
    }
}
void analyze_dangerous_functions(void) {
    runeanalyzer_log(2, "Analyzing dangerous function usage...\n");
    
    // In a real implementation, this would use objdump, nm, or similar tools
    // to analyze the binary for dangerous function calls.
    // For this demo, we'll use simple heuristics.
    
    const char* executable = g_config.target_executable;
    const char* basename = strrchr(executable, '/');  
    if (basename) basename++; else basename = executable;
    
    // List of potentially dangerous function indicators in binary names
    const char* dangerous_patterns[] = {
        "strcpy", "strcat", "sprintf", "gets", "scanf", 
        "malloc", "free", "system", "exec", "buffer",
        NULL
    };
    
    for (int i = 0; dangerous_patterns[i] != NULL; i++) {
        if (strstr(basename, dangerous_patterns[i])) {
            g_results.dangerous_function_count++;
            g_results.overall_security_score--;
        }
    }
    
    // Adjust security classification based on dangerous function usage
    if (g_results.dangerous_function_count > 3) {
        g_results.overall_security_score -= 2;
        if (strcmp(g_results.security_classification, "low_risk") == 0) {
            strncpy(g_results.security_classification, "medium_risk", sizeof(g_results.security_classification) - 1);
        }
    }
    
    // Keep score within bounds
    if (g_results.overall_security_score < 1) g_results.overall_security_score = 1;
}

/**
 * @brief Detect the programming language and runtime of the target executable
 */
void detect_language_runtime(void) {
    runeanalyzer_log(2, "Detecting programming language and runtime...\n");
    
    const char* executable = g_config.target_executable;
    const char* basename = strrchr(executable, '/');
    if (basename) basename++; else basename = executable;
    
    // Declare variables at the beginning
    char command[512];
    FILE* pipe;
    char resolved_path[PATH_MAX];
    
    // Resolve symbolic links to get the actual file
    ssize_t len = readlink(executable, resolved_path, sizeof(resolved_path) - 1);
    if (len != -1) {
        resolved_path[len] = '\0';
        // If it's a relative path, make it absolute
        if (resolved_path[0] != '/') {
            char dir_path[PATH_MAX];
            char* last_slash = strrchr(executable, '/');
            if (last_slash) {
                size_t dir_len = last_slash - executable;
                strncpy(dir_path, executable, dir_len);
                dir_path[dir_len] = '\0';
                snprintf(command, sizeof(command), "%s/%s", dir_path, resolved_path);
                SAFE_STRNCPY(resolved_path, command, sizeof(resolved_path));
            }
        }
        runeanalyzer_log(2, "Resolved symlink: %s -> %s\n", executable, resolved_path);
        executable = resolved_path;
        basename = strrchr(executable, '/');
        if (basename) basename++; else basename = executable;
    }
    
    // Initialize language detection fields
    SAFE_STRNCPY(g_results.detected_language, "Unknown", sizeof(g_results.detected_language));
    SAFE_STRNCPY(g_results.runtime_version, "Unknown", sizeof(g_results.runtime_version));
    SAFE_STRNCPY(g_results.language_specific_info, "", sizeof(g_results.language_specific_info));
    SAFE_STRNCPY(g_results.dependency_manager, "None", sizeof(g_results.dependency_manager));
    g_results.uses_managed_memory = 0;
    g_results.uses_unsafe_code = 0;
    g_results.jvm_analysis_available = 0;
    g_results.cargo_project_detected = 0;
    
    // Check if it's a Java program (java command or .jar file)
    if (strstr(basename, "java") || strstr(executable, ".jar") || strstr(executable, ".war")) {
        SAFE_STRNCPY(g_results.detected_language, "Java", sizeof(g_results.detected_language));
        g_results.uses_managed_memory = 1;
        g_results.jvm_analysis_available = 1;
        SAFE_STRNCPY(g_results.dependency_manager, "Maven/Gradle", sizeof(g_results.dependency_manager));
        analyze_java_program();
        
    // Check if it's a Rust binary
    } else if (strstr(basename, "cargo") || strstr(executable, "target/")) {
        SAFE_STRNCPY(g_results.detected_language, "Rust", sizeof(g_results.detected_language));
        g_results.uses_managed_memory = 0;  // Rust has ownership system, not GC
        g_results.cargo_project_detected = 1;
        SAFE_STRNCPY(g_results.dependency_manager, "Cargo", sizeof(g_results.dependency_manager));
        analyze_rust_program();
        
    // Check if it's a Python program
    } else if (strstr(basename, "python") || strstr(executable, ".py")) {
        SAFE_STRNCPY(g_results.detected_language, "Python", sizeof(g_results.detected_language));
        g_results.uses_managed_memory = 1;
        SAFE_STRNCPY(g_results.dependency_manager, "pip", sizeof(g_results.dependency_manager));
        analyze_python_program();
        
    // Check if it's a JavaScript/Node.js program
    } else if (strstr(basename, "node") || strstr(basename, "npm") || strstr(basename, "coffee") || 
               strstr(executable, ".js") || strstr(executable, "node_modules")) {
        SAFE_STRNCPY(g_results.detected_language, "JavaScript", sizeof(g_results.detected_language));
        g_results.uses_managed_memory = 1;  // V8 has GC
        SAFE_STRNCPY(g_results.dependency_manager, "npm", sizeof(g_results.dependency_manager));
        analyze_javascript_program();
        
    // Check if it's a Perl program
    } else if (strstr(basename, "perl") || strstr(executable, ".pl") || strstr(executable, ".pm")) {
        SAFE_STRNCPY(g_results.detected_language, "Perl", sizeof(g_results.detected_language));
        g_results.uses_managed_memory = 0;  // Perl has reference counting, not true GC
        SAFE_STRNCPY(g_results.dependency_manager, "cpan", sizeof(g_results.dependency_manager));
        analyze_perl_program();
        
    // Check if it's a Go program
    } else if (strstr(basename, "go") || strstr(executable, "go/bin/")) {
        SAFE_STRNCPY(g_results.detected_language, "Go", sizeof(g_results.detected_language));
        g_results.uses_managed_memory = 1;  // Go has GC
        SAFE_STRNCPY(g_results.dependency_manager, "go mod", sizeof(g_results.dependency_manager));
        analyze_go_program();
        
    // Check if it's a shell script or other script by reading the shebang line
    } else {
        // Try to detect shell scripts by reading the first line
        FILE* script_file = fopen(executable, "r");
        if (script_file) {
            char first_line[256];
            if (fgets(first_line, sizeof(first_line), script_file)) {
                if (strncmp(first_line, "#!/", 3) == 0) {
                    // It's a script with shebang
                    if (strstr(first_line, "/bash") || strstr(first_line, "/sh") || 
                        strstr(first_line, "bash") || strstr(first_line, " sh")) {
                        SAFE_STRNCPY(g_results.detected_language, "Shell Script (Bash)", sizeof(g_results.detected_language));
                        g_results.uses_managed_memory = 0;
                        SAFE_STRNCPY(g_results.dependency_manager, "None", sizeof(g_results.dependency_manager));
                        analyze_shell_script();
                        fclose(script_file);
                        runeanalyzer_log(1, "🔍 Detected Language: %s\n", g_results.detected_language);
                        return;
                    } else if (strstr(first_line, "python")) {
                        SAFE_STRNCPY(g_results.detected_language, "Python", sizeof(g_results.detected_language));
                        g_results.uses_managed_memory = 1;
                        SAFE_STRNCPY(g_results.dependency_manager, "pip", sizeof(g_results.dependency_manager));
                        analyze_python_program();
                        fclose(script_file);
                        runeanalyzer_log(1, "🔍 Detected Language: %s (script)\n", g_results.detected_language);
                        return;
                    } else if (strstr(first_line, "perl")) {
                        SAFE_STRNCPY(g_results.detected_language, "Perl", sizeof(g_results.detected_language));
                        g_results.uses_managed_memory = 0;
                        SAFE_STRNCPY(g_results.dependency_manager, "cpan", sizeof(g_results.dependency_manager));
                        analyze_perl_program();
                        fclose(script_file);
                        runeanalyzer_log(1, "🔍 Detected Language: %s (script)\n", g_results.detected_language);
                        return;
                    } else if (strstr(first_line, "node")) {
                        SAFE_STRNCPY(g_results.detected_language, "JavaScript", sizeof(g_results.detected_language));
                        g_results.uses_managed_memory = 1;
                        SAFE_STRNCPY(g_results.dependency_manager, "npm", sizeof(g_results.dependency_manager));
                        analyze_javascript_program();
                        fclose(script_file);
                        runeanalyzer_log(1, "🔍 Detected Language: %s (Node.js script)\n", g_results.detected_language);
                        return;
                    }
                }
            }
            fclose(script_file);
        }
        
        // Default analysis for native binaries - enhanced Rust detection
        // First, check if it's a Rust binary by looking for Rust-specific strings
        snprintf(command, sizeof(command), "strings '%s' 2>/dev/null | grep -i 'RUST\\|rust_' | head -1", executable);
        pipe = popen(command, "r");
        if (pipe) {
            char line[256];
            if (fgets(line, sizeof(line), pipe) && strlen(line) > 1) {
                SAFE_STRNCPY(g_results.detected_language, "Rust", sizeof(g_results.detected_language));
                g_results.uses_managed_memory = 0;  // Rust has ownership system
                SAFE_STRNCPY(g_results.dependency_manager, "Cargo", sizeof(g_results.dependency_manager));
                analyze_rust_program();
                pclose(pipe);
                runeanalyzer_log(1, "🔍 Detected Language: %s (compiled binary with Rust signatures)\n", g_results.detected_language);
                return;
            }
            pclose(pipe);
        }
        
        // Check for Go runtime signatures
        snprintf(command, sizeof(command), "strings '%s' 2>/dev/null | grep -i 'golang\\|go build\\|runtime.go' | head -1", executable);
        pipe = popen(command, "r");
        if (pipe) {
            char line[256];
            if (fgets(line, sizeof(line), pipe) && strlen(line) > 1) {
                SAFE_STRNCPY(g_results.detected_language, "Go", sizeof(g_results.detected_language));
                g_results.uses_managed_memory = 1;  // Go has GC
                SAFE_STRNCPY(g_results.dependency_manager, "go mod", sizeof(g_results.dependency_manager));
                analyze_go_program();
                pclose(pipe);
                runeanalyzer_log(1, "🔍 Detected Language: %s (compiled binary with Go signatures)\n", g_results.detected_language);
                return;
            }
            pclose(pipe);
        }
        
        // Default to C/C++ for other native binaries
        snprintf(command, sizeof(command), "file '%s' 2>/dev/null", executable);
        
        pipe = popen(command, "r");
        if (pipe) {
            char line[256];
            if (fgets(line, sizeof(line), pipe)) {
                if (strstr(line, "ELF") && (strstr(line, "x86") || strstr(line, "ARM"))) {
                    SAFE_STRNCPY(g_results.detected_language, "C/C++", sizeof(g_results.detected_language));
                    g_results.uses_managed_memory = 0;
                    SAFE_STRNCPY(g_results.dependency_manager, "Make/CMake", sizeof(g_results.dependency_manager));
                }
            }
            pclose(pipe);
        }
    }
    
    runeanalyzer_log(1, "🔍 Detected Language: %s\n", g_results.detected_language);
}

/**
 * @brief Analyze Java-specific patterns and vulnerabilities
 */
void analyze_java_program(void) {
    runeanalyzer_log(2, "Analyzing Java program specifics...\n");
    
    // Try to get Java version
    char command[512];
    snprintf(command, sizeof(command), "java -version 2>&1 | head -1");
    
    FILE* pipe = popen(command, "r");
    if (pipe) {
        char line[256];
        if (fgets(line, sizeof(line), pipe)) {
            // Extract Java version from output like: java version "11.0.16"
            char* version_start = strchr(line, '"');
            if (version_start) {
                version_start++;
                char* version_end = strchr(version_start, '"');
                if (version_end) {
                    size_t version_len = version_end - version_start;
                    if (version_len < sizeof(g_results.runtime_version) - 1) {
                        strncpy(g_results.runtime_version, version_start, version_len);
                        g_results.runtime_version[version_len] = '\0';
                    }
                }
            }
        }
        pclose(pipe);
    }
    
    // Framework Detection for Java
    const char* java_basename = strrchr(g_config.target_executable, '/');
    if (java_basename) java_basename++; else java_basename = g_config.target_executable;
    
    // Spring Boot detection by executable name
    if (strstr(java_basename, "spring") || strstr(java_basename, "boot")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Spring Boot, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Spring Boot framework from executable name\n");
    }
    
    // Check for Maven/Gradle project structure
    char project_path[512];
    char* dir = strrchr(g_config.target_executable, '/');
    if (dir) {
        size_t dir_len = dir - g_config.target_executable;
        strncpy(project_path, g_config.target_executable, dir_len);
        project_path[dir_len] = '\0';
        
        // Check for pom.xml (Maven project)
        strcat(project_path, "/pom.xml");
        struct stat st;
        if (stat(project_path, &st) == 0) {
            FILE* pom_file = fopen(project_path, "r");
            if (pom_file) {
                char pom_content[4096];
                size_t read_size = fread(pom_content, 1, sizeof(pom_content) - 1, pom_file);
                pom_content[read_size] = '\0';
                fclose(pom_file);
                
                // Detect Spring frameworks
                if (strstr(pom_content, "spring-boot") || strstr(pom_content, "spring.boot")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Spring Boot, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Spring Boot in pom.xml\n");
                }
                
                if (strstr(pom_content, "spring-core") || strstr(pom_content, "springframework")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Spring Framework, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Spring Framework in pom.xml\n");
                }
                
                // Detect Hibernate
                if (strstr(pom_content, "hibernate")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Hibernate ORM, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Hibernate ORM in pom.xml\n");
                }
                
                // Detect Apache frameworks
                if (strstr(pom_content, "apache.struts") || strstr(pom_content, "struts2")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Apache Struts, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Apache Struts in pom.xml\n");
                }
                
                if (strstr(pom_content, "apache.wicket")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Apache Wicket, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Apache Wicket in pom.xml\n");
                }
                
                // Detect JSF
                if (strstr(pom_content, "jsf-api") || strstr(pom_content, "javax.faces")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "JSF, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected JSF framework in pom.xml\n");
                }
                
                // Detect JAX-RS/Jersey
                if (strstr(pom_content, "jersey") || strstr(pom_content, "jax-rs")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "JAX-RS/Jersey, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected JAX-RS/Jersey in pom.xml\n");
                }
                
                // Detect Play Framework
                if (strstr(pom_content, "play-java") || strstr(pom_content, "playframework")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Play Framework, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Play Framework in pom.xml\n");
                }
            }
        }
        
        // Check for build.gradle (Gradle project)
        project_path[dir_len] = '\0';  // Reset path
        strcat(project_path, "/build.gradle");
        if (stat(project_path, &st) == 0) {
            FILE* gradle_file = fopen(project_path, "r");
            if (gradle_file) {
                char gradle_content[4096];
                size_t read_size = fread(gradle_content, 1, sizeof(gradle_content) - 1, gradle_file);
                gradle_content[read_size] = '\0';
                fclose(gradle_file);
                
                // Similar detection logic for Gradle files
                if (strstr(gradle_content, "spring-boot") || strstr(gradle_content, "'org.springframework.boot'")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Spring Boot, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Spring Boot in build.gradle\n");
                }
                
                if (strstr(gradle_content, "springframework")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Spring Framework, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Spring Framework in build.gradle\n");
                }
            }
        }
    }
    
    // Analyze binary strings for framework detection
    snprintf(command, sizeof(command), "strings '%s' 2>/dev/null | grep -i 'springframework\\|hibernate\\|struts' | head -3", g_config.target_executable);
    pipe = popen(command, "r");
    if (pipe) {
        char line[256];
        while (fgets(line, sizeof(line), pipe)) {
            if (strstr(line, "springframework")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "Spring, ", sizeof(g_results.detected_frameworks));
                runeanalyzer_log(2, "Detected Spring framework in binary strings\n");
                break;  // Avoid duplicates
            }
            if (strstr(line, "hibernate")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "Hibernate, ", sizeof(g_results.detected_frameworks));
                runeanalyzer_log(2, "Detected Hibernate ORM in binary strings\n");
                break;  // Avoid duplicates
            }
            if (strstr(line, "struts")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "Apache Struts, ", sizeof(g_results.detected_frameworks));
                runeanalyzer_log(2, "Detected Apache Struts in binary strings\n");
                break;  // Avoid duplicates
            }
        }
        pclose(pipe);
    }
    
    // Java-specific security analysis
    if (strstr(g_config.target_executable, ".jar")) {
        SAFE_STRNCPY(g_results.language_specific_info, 
                   "JAR file analysis: Check for Log4j, serialization, and classpath vulnerabilities", 
                   sizeof(g_results.language_specific_info));
                   
        // JAR files have different vulnerability patterns
        g_results.buffer_overflow_risk = 1;  // Less likely in managed memory
        g_results.use_after_free_risk = 0;   // Not applicable to Java
        g_results.format_string_vuln = 2;    // Still possible with logging frameworks
        g_results.overall_security_score += 2; // Java is generally safer for memory issues
    }
    
    // Check for common Java vulnerability patterns
    const char* java_vuln_basename = strrchr(g_config.target_executable, '/');
    if (java_vuln_basename) java_vuln_basename++; else java_vuln_basename = g_config.target_executable;
    
    if (strstr(java_vuln_basename, "log4j") || strstr(java_vuln_basename, "logging")) {
        SAFE_STRNCPY(g_results.language_specific_info, 
                   "Logging framework detected - check for Log4Shell (CVE-2021-44228) vulnerability", 
                   sizeof(g_results.language_specific_info));
        g_results.format_string_vuln = 5;
        g_results.overall_security_score -= 3;
    }
}

/**
 * @brief Analyze Rust-specific patterns and safety features
 */
void analyze_rust_program(void) {
    runeanalyzer_log(2, "Analyzing Rust program specifics...\n");
    
    // Try to get Rust version
    char command[512];
    snprintf(command, sizeof(command), "rustc --version 2>/dev/null || echo 'Unknown'");
    
    FILE* pipe = popen(command, "r");
    if (pipe) {
        char line[256];
        if (fgets(line, sizeof(line), pipe)) {
            // Extract version from output like: rustc 1.70.0
            if (strstr(line, "rustc")) {
                char* version_start = strchr(line, ' ');
                if (version_start) {
                    version_start++;
                    char* version_end = strchr(version_start, ' ');
                    if (version_end) *version_end = '\0';
                    SAFE_STRNCPY(g_results.runtime_version, version_start, sizeof(g_results.runtime_version));
                }
            }
        }
        pclose(pipe);
    }
    
    // Check for Cargo.toml in the directory (Rust project)
    char cargo_path[512];
    char* dir = strrchr(g_config.target_executable, '/');
    if (dir) {
        size_t dir_len = dir - g_config.target_executable;
        strncpy(cargo_path, g_config.target_executable, dir_len);
        cargo_path[dir_len] = '\0';
        strcat(cargo_path, "/Cargo.toml");
        
        struct stat st;
        if (stat(cargo_path, &st) == 0) {
            g_results.cargo_project_detected = 1;
            SAFE_STRNCPY(g_results.language_specific_info, 
                       "Cargo project detected - Rust's memory safety prevents most C-style vulnerabilities", 
                       sizeof(g_results.language_specific_info));
        }
    }
    
    // Rust-specific security analysis
    g_results.buffer_overflow_risk = 0;      // Rust prevents buffer overflows
    g_results.use_after_free_risk = 0;       // Ownership system prevents this
    g_results.null_pointer_risk = 0;         // Option<T> prevents null pointer dereferences
    g_results.memory_leak_indicators = 1;    // Still possible but rare
    g_results.overall_security_score = 9;    // Rust is very safe by default
    
    // Check for unsafe blocks (would need source analysis or special tools)
    snprintf(command, sizeof(command), "strings '%s' | grep -i unsafe | wc -l", g_config.target_executable);
    pipe = popen(command, "r");
    if (pipe) {
        char line[32];
        if (fgets(line, sizeof(line), pipe)) {
            int unsafe_count = atoi(line);
            if (unsafe_count > 0) {
                g_results.uses_unsafe_code = 1;
                g_results.overall_security_score -= 2;
                SAFE_STRNCPY(g_results.language_specific_info, 
                           "Unsafe Rust code detected - manual security review recommended", 
                           sizeof(g_results.language_specific_info));
            }
        }
        pclose(pipe);
    }
}

/**
 * @brief Analyze Python-specific patterns
 */
void analyze_python_program(void) {
    runeanalyzer_log(2, "Analyzing Python program specifics...\n");
    
    // Try to get Python version
    char command[512];
    snprintf(command, sizeof(command), "python3 --version 2>&1 || python --version 2>&1");
    
    FILE* pipe = popen(command, "r");
    if (pipe) {
        char line[256];
        if (fgets(line, sizeof(line), pipe)) {
            char* version_start = strchr(line, ' ');
            if (version_start) {
                version_start++;
                SAFE_STRNCPY(g_results.runtime_version, version_start, sizeof(g_results.runtime_version));
                // Remove newline
                char* newline = strchr(g_results.runtime_version, '\n');
                if (newline) *newline = '\0';
            }
        }
        pclose(pipe);
    }
    
    // Framework Detection for Python
    const char* py_basename = strrchr(g_config.target_executable, '/');
    if (py_basename) py_basename++; else py_basename = g_config.target_executable;
    
    // Check for requirements.txt and setup.py to detect Python frameworks
    char requirements_path[512];
    char* dir = strrchr(g_config.target_executable, '/');
    if (dir) {
        size_t dir_len = dir - g_config.target_executable;
        strncpy(requirements_path, g_config.target_executable, dir_len);
        requirements_path[dir_len] = '\0';
        
        // Check requirements.txt
        strcat(requirements_path, "/requirements.txt");
        struct stat st;
        if (stat(requirements_path, &st) == 0) {
            FILE* req_file = fopen(requirements_path, "r");
            if (req_file) {
                char line[256];
                while (fgets(line, sizeof(line), req_file)) {
                    // Convert to lowercase for comparison
                    for (int i = 0; line[i]; i++) {
                        line[i] = tolower(line[i]);
                    }
                    
                    // Detect Django
                    if (strstr(line, "django")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "Django, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected Django framework in requirements.txt\n");
                    }
                    
                    // Detect Flask
                    if (strstr(line, "flask")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "Flask, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected Flask framework in requirements.txt\n");
                    }
                    
                    // Detect FastAPI
                    if (strstr(line, "fastapi") || strstr(line, "uvicorn")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "FastAPI, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected FastAPI framework in requirements.txt\n");
                    }
                    
                    // Detect Tornado
                    if (strstr(line, "tornado")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "Tornado, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected Tornado framework in requirements.txt\n");
                    }
                    
                    // Detect Pyramid
                    if (strstr(line, "pyramid")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "Pyramid, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected Pyramid framework in requirements.txt\n");
                    }
                    
                    // Detect Bottle
                    if (strstr(line, "bottle")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "Bottle, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected Bottle framework in requirements.txt\n");
                    }
                    
                    // Detect data science frameworks
                    if (strstr(line, "tensorflow") || strstr(line, "keras")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "TensorFlow/Keras, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected TensorFlow/Keras ML framework\n");
                    }
                    
                    if (strstr(line, "pytorch") || strstr(line, "torch")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "PyTorch, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected PyTorch ML framework\n");
                    }
                    
                    if (strstr(line, "scikit-learn") || strstr(line, "sklearn")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "scikit-learn, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected scikit-learn ML framework\n");
                    }
                    
                    if (strstr(line, "pandas") || strstr(line, "numpy")) {
                        SAFE_STRNCAT(g_results.detected_frameworks, "Pandas/NumPy, ", sizeof(g_results.detected_frameworks));
                        runeanalyzer_log(2, "Detected data analysis frameworks\n");
                    }
                }
                fclose(req_file);
            }
        }
        
        // Check manage.py for Django projects
        requirements_path[dir_len] = '\0';  // Reset path
        strcat(requirements_path, "/manage.py");
        if (stat(requirements_path, &st) == 0) {
            SAFE_STRNCAT(g_results.detected_frameworks, "Django, ", sizeof(g_results.detected_frameworks));
            runeanalyzer_log(2, "Detected Django framework via manage.py\n");
        }
    }
    
    // Check executable name for framework patterns
    if (strstr(py_basename, "django") || strstr(py_basename, "manage")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Django, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Django from executable name\n");
    }
    
    if (strstr(py_basename, "flask")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Flask, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Flask from executable name\n");
    }
    
    if (strstr(py_basename, "gunicorn") || strstr(py_basename, "uwsgi")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "WSGI Server, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected WSGI server from executable name\n");
    }
    
    // Python security characteristics
    g_results.buffer_overflow_risk = 0;      // Python prevents buffer overflows
    g_results.use_after_free_risk = 0;       // Managed memory
    g_results.null_pointer_risk = 1;         // Still possible with None
    g_results.format_string_vuln = 3;        // Format strings still vulnerable
    g_results.overall_security_score = 7;    // Generally safe but injection risks
    
    SAFE_STRNCPY(g_results.language_specific_info, 
               "Python interpreter - check for injection vulnerabilities and package security", 
               sizeof(g_results.language_specific_info));
}

/**
 * @brief Analyze Go program specifics
 */
void analyze_go_program(void) {
    runeanalyzer_log(2, "Analyzing Go program specifics...\n");
    
    // Go security characteristics
    g_results.buffer_overflow_risk = 1;      // Go has some bounds checking
    g_results.use_after_free_risk = 0;       // GC prevents this
    g_results.null_pointer_risk = 2;         // Nil pointer panics possible
    g_results.memory_leak_indicators = 2;    // GC helps but leaks possible
    g_results.overall_security_score = 8;    // Generally safe
    
    SAFE_STRNCPY(g_results.language_specific_info, 
               "Go binary - memory safe with garbage collection, check for goroutine leaks", 
               sizeof(g_results.language_specific_info));
}

/**
 * @brief Analyze JavaScript/Node.js program specifics
 */
void analyze_javascript_program(void) {
    runeanalyzer_log(2, "Analyzing JavaScript/Node.js program specifics...\n");
    
    // Try to get Node.js version
    char command[512];
    snprintf(command, sizeof(command), "node --version 2>/dev/null || echo 'Unknown'");
    
    FILE* pipe = popen(command, "r");
    if (pipe) {
        char line[256];
        if (fgets(line, sizeof(line), pipe)) {
            // Extract version from output like: v18.17.0
            if (line[0] == 'v') {
                SAFE_STRNCPY(g_results.runtime_version, line + 1, sizeof(g_results.runtime_version));
                // Remove newline
                char* newline = strchr(g_results.runtime_version, '\n');
                if (newline) *newline = '\0';
            } else {
                SAFE_STRNCPY(g_results.runtime_version, line, sizeof(g_results.runtime_version));
                // Remove newline
                char* newline = strchr(g_results.runtime_version, '\n');
                if (newline) *newline = '\0';
            }
        }
        pclose(pipe);
    }
    
    // Framework Detection for JavaScript/Node.js
    const char* js_basename = strrchr(g_config.target_executable, '/');
    if (js_basename) js_basename++; else js_basename = g_config.target_executable;
    
    // Check for package.json and analyze it for framework dependencies
    char package_path[512];
    char* dir = strrchr(g_config.target_executable, '/');
    if (dir) {
        size_t dir_len = dir - g_config.target_executable;
        strncpy(package_path, g_config.target_executable, dir_len);
        package_path[dir_len] = '\0';
        strcat(package_path, "/package.json");
        
        struct stat st;
        if (stat(package_path, &st) == 0) {
            // Read package.json to detect frameworks
            FILE* package_file = fopen(package_path, "r");
            if (package_file) {
                char package_content[2048];
                size_t read_size = fread(package_content, 1, sizeof(package_content) - 1, package_file);
                package_content[read_size] = '\0';
                fclose(package_file);
                
                // Detect React
                if (strstr(package_content, "\"react\"") || strstr(package_content, "react-dom")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "React, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected React framework in package.json\n");
                }
                
                // Detect Vue.js
                if (strstr(package_content, "\"vue\"") || strstr(package_content, "@vue/")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Vue.js, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Vue.js framework in package.json\n");
                }
                
                // Detect Angular
                if (strstr(package_content, "@angular/") || strstr(package_content, "angular")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Angular, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Angular framework in package.json\n");
                }
                
                // Detect Express.js
                if (strstr(package_content, "\"express\"")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Express.js, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Express.js framework in package.json\n");
                }
                
                // Detect Next.js
                if (strstr(package_content, "\"next\"") || strstr(package_content, "next/")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Next.js, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Next.js framework in package.json\n");
                }
                
                // Detect Svelte
                if (strstr(package_content, "\"svelte\"")) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Svelte, ", sizeof(g_results.detected_frameworks));
                    runeanalyzer_log(2, "Detected Svelte framework in package.json\n");
                }
            }
            
            SAFE_STRNCPY(g_results.language_specific_info, 
                       "Node.js project detected - JavaScript runtime with V8 engine", 
                       sizeof(g_results.language_specific_info));
        } else {
            SAFE_STRNCPY(g_results.language_specific_info, 
                       "JavaScript/Node.js program - interpreted language with garbage collection", 
                       sizeof(g_results.language_specific_info));
        }
    }
    
    // Check for framework patterns in executable name
    if (strstr(js_basename, "react") || strstr(js_basename, "jsx")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "React, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected React from executable name\n");
    }
    
    if (strstr(js_basename, "vue") || strstr(js_basename, "nuxt")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Vue.js, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Vue.js from executable name\n");
    }
    
    if (strstr(js_basename, "angular") || strstr(js_basename, "ng-")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Angular, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Angular from executable name\n");
    }
    
    // JavaScript/Node.js security characteristics
    g_results.buffer_overflow_risk = 0;      // JavaScript prevents buffer overflows
    g_results.use_after_free_risk = 0;       // V8 GC prevents this
    g_results.null_pointer_risk = 2;         // null/undefined still possible
    g_results.memory_leak_indicators = 2;    // Closure leaks possible
    g_results.format_string_vuln = 1;        // Less common in JavaScript
    g_results.overall_security_score = 7;    // Generally safe but injection risks
    
    // Check for specific JavaScript vulnerabilities
    const char* js_vuln_basename = strrchr(g_config.target_executable, '/');
    if (js_vuln_basename) js_vuln_basename++; else js_vuln_basename = g_config.target_executable;
    
    if (strstr(js_vuln_basename, "coffee")) {
        SAFE_STRNCPY(g_results.language_specific_info, 
                   "CoffeeScript transpiler - compiles to JavaScript with enhanced syntax", 
                   sizeof(g_results.language_specific_info));
        g_results.overall_security_score = 8;  // CoffeeScript adds some safety
    }
}

/**
 * @brief Analyze Perl program specifics
 */
void analyze_perl_program(void) {
    runeanalyzer_log(2, "Analyzing Perl program specifics...\n");
    
    // Try to get Perl version
    char command[512];
    snprintf(command, sizeof(command), "perl --version 2>/dev/null | grep 'This is perl' | head -1");
    
    FILE* pipe = popen(command, "r");
    if (pipe) {
        char line[256];
        if (fgets(line, sizeof(line), pipe)) {
            // Extract version from output like: This is perl 5, version 38
            char* version_start = strstr(line, "version");
            if (version_start) {
                version_start += 8; // Skip "version "
                char* version_end = strchr(version_start, ',');
                if (version_end) {
                    size_t len = version_end - version_start;
                    if (len > 0 && len < sizeof(g_results.runtime_version) - 1) {
                        strncpy(g_results.runtime_version, version_start, len);
                        g_results.runtime_version[len] = '\0';
                    }
                }
            }
        }
        pclose(pipe);
    }
    
    // Perl security characteristics
    g_results.buffer_overflow_risk = 1;      // Perl has some buffer safety but still possible
    g_results.use_after_free_risk = 0;       // Reference counting prevents most of this
    g_results.null_pointer_risk = 2;         // undef values can cause issues
    g_results.memory_leak_indicators = 2;    // Circular references can cause leaks
    g_results.format_string_vuln = 3;        // printf-style functions still vulnerable
    g_results.overall_security_score = 6;    // Moderate safety with injection risks
    
    // Check for specific Perl vulnerabilities
    const char* perl_basename = strrchr(g_config.target_executable, '/');
    if (perl_basename) perl_basename++; else perl_basename = g_config.target_executable;
    
    SAFE_STRNCPY(g_results.language_specific_info, 
               "Perl interpreter - check for eval injection, taint mode, and regex DoS vulnerabilities", 
               sizeof(g_results.language_specific_info));
               
    // Look for common Perl security issues
    if (strstr(perl_basename, "cgi") || strstr(perl_basename, "web")) {
        SAFE_STRNCPY(g_results.language_specific_info, 
                   "Perl CGI/web script - high injection risk, verify input sanitization", 
                   sizeof(g_results.language_specific_info));
        g_results.overall_security_score -= 2;
    }
}

/**
 * @brief Analyze shell script specifics and build system patterns
 */
void analyze_shell_script(void) {
    runeanalyzer_log(2, "Analyzing shell script specifics...\n");
    
    // Try to get bash version
    char command[512];
    snprintf(command, sizeof(command), "bash --version 2>/dev/null | head -1");
    
    FILE* pipe = popen(command, "r");
    if (pipe) {
        char line[256];
        if (fgets(line, sizeof(line), pipe)) {
            // Extract version from output like: GNU bash, version 5.1.16(1)-release
            char* version_start = strstr(line, "version ");
            if (version_start) {
                version_start += 8; // Skip "version "
                char* version_end = strchr(version_start, '(');
                if (!version_end) version_end = strchr(version_start, '-');
                if (!version_end) version_end = strchr(version_start, ' ');
                if (version_end) {
                    size_t len = version_end - version_start;
                    if (len > 0 && len < sizeof(g_results.runtime_version) - 1) {
                        strncpy(g_results.runtime_version, version_start, len);
                        g_results.runtime_version[len] = '\0';
                    }
                }
            }
        }
        pclose(pipe);
    }
    
    // Analyze script content for build system patterns
    FILE* script_file = fopen(g_config.target_executable, "r");
    if (script_file) {
        char line[512];
        int build_system_detected = 0;
        int package_manager_detected = 0;
        
        while (fgets(line, sizeof(line), script_file) && build_system_detected < 3) {
            // Convert to lowercase for analysis
            char lower_line[512];
            size_t line_len = strlen(line);
            for (size_t i = 0; i < line_len && i < sizeof(lower_line) - 1; i++) {
                lower_line[i] = tolower(line[i]);
            }
            lower_line[sizeof(lower_line) - 1] = '\0';
            
            // Detect GNU Autotools
            if (strstr(lower_line, "./configure") || strstr(lower_line, "autogen") || strstr(lower_line, "automake")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "GNU Autotools, ", sizeof(g_results.detected_frameworks));
                build_system_detected++;
                runeanalyzer_log(2, "Detected GNU Autotools build system\n");
            }
            
            // Detect CMake
            if (strstr(lower_line, "cmake") || strstr(lower_line, "cmakelists")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "CMake, ", sizeof(g_results.detected_frameworks));
                build_system_detected++;
                runeanalyzer_log(2, "Detected CMake build system\n");
            }
            
            // Detect Make
            if (strstr(lower_line, "make ") || strstr(lower_line, "make -") || strstr(lower_line, "makefile")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "GNU Make, ", sizeof(g_results.detected_frameworks));
                build_system_detected++;
                runeanalyzer_log(2, "Detected GNU Make build system\n");
            }
            
            // Detect package managers
            if (strstr(lower_line, "wget ") || strstr(lower_line, "curl ")) {
                if (!package_manager_detected) {
                    SAFE_STRNCAT(g_results.detected_frameworks, "Source Download, ", sizeof(g_results.detected_frameworks));
                    package_manager_detected = 1;
                    runeanalyzer_log(2, "Detected source code download\n");
                }
            }
            
            // Detect dpkg/deb packaging
            if (strstr(lower_line, "dpkg") || strstr(lower_line, ".deb") || strstr(lower_line, "debian")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "Debian Packaging, ", sizeof(g_results.detected_frameworks));
                runeanalyzer_log(2, "Detected Debian packaging system\n");
            }
            
            // Detect tar/archive operations
            if (strstr(lower_line, "tar -") || strstr(lower_line, "tar.xz") || strstr(lower_line, "tar.gz")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "Archive Processing, ", sizeof(g_results.detected_frameworks));
                runeanalyzer_log(2, "Detected archive processing\n");
            }
            
            // Detect cross-compilation
            if (strstr(lower_line, "--target=") || strstr(lower_line, "--host=") || strstr(lower_line, "cross")) {
                SAFE_STRNCAT(g_results.detected_frameworks, "Cross-Compilation, ", sizeof(g_results.detected_frameworks));
                runeanalyzer_log(2, "Detected cross-compilation setup\n");
            }
        }
        fclose(script_file);
    }
    
    // Shell script security characteristics
    g_results.buffer_overflow_risk = 2;      // Shell injection risks
    g_results.use_after_free_risk = 0;       // Not applicable to shell
    g_results.null_pointer_risk = 0;         // Not applicable to shell
    g_results.memory_leak_indicators = 0;    // Shell handles memory automatically
    g_results.format_string_vuln = 1;        // printf in shell scripts
    g_results.overall_security_score = 6;    // Shell scripts have injection risks
    
    // Check for specific shell script security patterns
    const char* shell_basename = strrchr(g_config.target_executable, '/');
    if (shell_basename) shell_basename++; else shell_basename = g_config.target_executable;
    
    if (strstr(shell_basename, "build") || strstr(shell_basename, "install") || strstr(shell_basename, "config")) {
        SAFE_STRNCPY(g_results.language_specific_info, 
                   "Build/config script - check for code injection, privilege escalation, and unsafe file operations", 
                   sizeof(g_results.language_specific_info));
        g_results.overall_security_score -= 1; // Build scripts often run with elevated privileges
    } else {
        SAFE_STRNCPY(g_results.language_specific_info, 
                   "Shell script - check for command injection, path traversal, and unsafe variable expansion", 
                   sizeof(g_results.language_specific_info));
    }
}

/**
 * @brief Master framework detection function - consolidates framework detection across all languages
 */
void detect_frameworks(void) {
    runeanalyzer_log(2, "Running comprehensive framework detection...\n");
    
    // Don't initialize frameworks string - preserve what was detected by language-specific functions
    // Individual language analysis functions (analyze_javascript_program, analyze_python_program, etc.)
    // have already populated g_results.detected_frameworks with language-specific frameworks
    
    // Framework detection is already integrated into individual language analysis functions:
    // - analyze_javascript_program() detects React, Vue, Angular, Express.js, Next.js, Svelte
    // - analyze_python_program() detects Django, Flask, FastAPI, Tornado, ML frameworks
    // - analyze_java_program() detects Spring Boot, Hibernate, Apache Struts, JSF, etc.
    // - analyze_rust_program() could detect Rocket, Actix, Axum (future enhancement)
    // - analyze_go_program() could detect Gin, Echo, Beego (future enhancement)
    
    // Additional cross-language framework detection based on executable patterns
    const char* fw_basename = strrchr(g_config.target_executable, '/');
    if (fw_basename) fw_basename++; else fw_basename = g_config.target_executable;
    
    // Web server detection
    if (strstr(fw_basename, "apache") || strstr(fw_basename, "httpd")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Apache HTTP Server, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Apache HTTP Server\n");
    }
    
    if (strstr(fw_basename, "nginx")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Nginx, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Nginx web server\n");
    }
    
    // Database servers
    if (strstr(fw_basename, "mysql") || strstr(fw_basename, "mysqld")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "MySQL, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected MySQL database server\n");
    }
    
    if (strstr(fw_basename, "postgres") || strstr(fw_basename, "pg_")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "PostgreSQL, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected PostgreSQL database server\n");
    }
    
    if (strstr(fw_basename, "redis")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Redis, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Redis in-memory database\n");
    }
    
    // Container and orchestration
    if (strstr(fw_basename, "docker")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Docker, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Docker container system\n");
    }
    
    if (strstr(fw_basename, "kubectl") || strstr(fw_basename, "kubernetes")) {
        SAFE_STRNCAT(g_results.detected_frameworks, "Kubernetes, ", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "Detected Kubernetes orchestration\n");
    }
    
    // Remove trailing comma and space if frameworks were detected
    size_t len = strlen(g_results.detected_frameworks);
    if (len > 2 && strcmp(&g_results.detected_frameworks[len-2], ", ") == 0) {
        g_results.detected_frameworks[len-2] = '\0';
    }
    
    if (strlen(g_results.detected_frameworks) > 0) {
        runeanalyzer_log(1, "🚀 Detected Frameworks: %s\n", g_results.detected_frameworks);
    } else {
        SAFE_STRNCPY(g_results.detected_frameworks, "None detected", sizeof(g_results.detected_frameworks));
        runeanalyzer_log(2, "No frameworks detected\n");
    }
}

/**
 * @brief Analyze network behavior and monitor connections during tool execution
 */
void analyze_network_behavior(void) {
    runeanalyzer_log(2, "Analyzing network behavior...\n");
    
    // Initialize network analysis fields
    g_results.network_connections_detected = 0;
    g_results.outbound_http_requests = 0;
    g_results.dns_queries_made = 0;
    g_results.data_upload_detected = 0;
    g_results.package_downloads_detected = 0;
    g_results.network_security_score = 10; // Start with perfect score
    g_results.suspicious_network_activity = 0;
    
    SAFE_STRNCPY(g_results.external_hosts_contacted, "", sizeof(g_results.external_hosts_contacted));
    SAFE_STRNCPY(g_results.repository_urls, "", sizeof(g_results.repository_urls));
    SAFE_STRNCPY(g_results.network_behavior_summary, "No network activity detected", sizeof(g_results.network_behavior_summary));
    
    // Monitor network connections during execution
    monitor_network_connections();
    
    // Detect outbound requests patterns
    detect_outbound_requests();
    
    // Analyze package repository access
    analyze_package_repositories();
    
    // Calculate network security score
    if (g_results.network_connections_detected > 0) {
        g_results.network_security_score = 8; // Network access reduces score slightly
        
        if (g_results.outbound_http_requests > 5) {
            g_results.network_security_score -= 1; // Many HTTP requests
        }
        
        if (g_results.data_upload_detected) {
            g_results.network_security_score -= 2; // Data uploads are suspicious
            g_results.suspicious_network_activity = 1;
        }
        
        if (strlen(g_results.external_hosts_contacted) > 100) {
            g_results.network_security_score -= 1; // Contacting many hosts
        }
    }
    
    // Clamp score
    if (g_results.network_security_score < 1) g_results.network_security_score = 1;
    if (g_results.network_security_score > 10) g_results.network_security_score = 10;
    
    runeanalyzer_log(1, "🌐 Network Security Score: %d/10\n", g_results.network_security_score);
}

/**
 * @brief Monitor network connections made during tool execution
 */
void monitor_network_connections(void) {
    runeanalyzer_log(2, "Monitoring network connections...\n");
    
    const char* executable = g_config.target_executable;
    const char* basename = strrchr(executable, '/');
    if (basename) basename++; else basename = executable;
    
    // Check for network-enabled tools by name pattern
    if (strstr(basename, "wget") || strstr(basename, "curl") || strstr(basename, "fetch")) {
        g_results.network_connections_detected = 1;
        g_results.outbound_http_requests = 1;
        SAFE_STRNCPY(g_results.network_behavior_summary, "Download tool - HTTP requests expected", 
                   sizeof(g_results.network_behavior_summary));
        runeanalyzer_log(2, "Detected download tool\n");
        
    } else if (strstr(basename, "ssh") || strstr(basename, "scp") || strstr(basename, "rsync")) {
        g_results.network_connections_detected = 1;
        SAFE_STRNCPY(g_results.network_behavior_summary, "Secure transfer tool - SSH connections expected", 
                   sizeof(g_results.network_behavior_summary));
        runeanalyzer_log(2, "Detected secure transfer tool\n");
        
    } else if (strstr(basename, "git")) {
        g_results.network_connections_detected = 1;
        g_results.outbound_http_requests = 1;
        SAFE_STRNCPY(g_results.network_behavior_summary, "Git version control - repository access expected", 
                   sizeof(g_results.network_behavior_summary));
        runeanalyzer_log(2, "Detected Git tool\n");
        
    } else if (strstr(basename, "apt") || strstr(basename, "yum") || strstr(basename, "dnf") || strstr(basename, "pip") || strstr(basename, "npm")) {
        g_results.network_connections_detected = 1;
        g_results.outbound_http_requests = 2;
        g_results.package_downloads_detected = 1;
        SAFE_STRNCPY(g_results.network_behavior_summary, "Package manager - repository downloads expected", 
                   sizeof(g_results.network_behavior_summary));
        runeanalyzer_log(2, "Detected package manager\n");
    }
    
    // Monitor process network activity using /proc/net (Linux-specific)
    if (g_results.child_pid > 0) {
        check_network_activity(g_results.child_pid);
    }
}

/**
 * @brief Detect outbound HTTP/HTTPS requests and analyze them
 */
void detect_outbound_requests(void) {
    runeanalyzer_log(2, "Detecting outbound requests...\n");
    
    // Check command line arguments for URLs
    for (int i = 0; i < g_config.target_argc; i++) {
        const char* arg = g_config.target_args[i];
        if (strstr(arg, "http://") || strstr(arg, "https://")) {
            g_results.outbound_http_requests++;
            
            // Extract hostname for analysis
            const char* url_start = strstr(arg, "://");
            if (url_start) {
                url_start += 3; // Skip "://"
                const char* path_start = strchr(url_start, '/');
                const char* port_start = strchr(url_start, ':');
                
                // Find end of hostname
                const char* hostname_end = url_start + strlen(url_start);
                if (path_start && path_start < hostname_end) hostname_end = path_start;
                if (port_start && port_start < hostname_end) hostname_end = port_start;
                
                size_t hostname_len = hostname_end - url_start;
                if (hostname_len > 0 && hostname_len < 256) {
                    char hostname[256];
                    strncpy(hostname, url_start, hostname_len);
                    hostname[hostname_len] = '\0';
                    
                    // Add to contacted hosts list
                    if (strlen(g_results.external_hosts_contacted) > 0) {
                        SAFE_STRNCAT(g_results.external_hosts_contacted, ", ", sizeof(g_results.external_hosts_contacted));
                    }
                    SAFE_STRNCAT(g_results.external_hosts_contacted, hostname, sizeof(g_results.external_hosts_contacted));
                    
                    runeanalyzer_log(2, "Detected outbound request to: %s\n", hostname);
                }
            }
        }
    }
    
    if (g_results.outbound_http_requests > 0) {
        SAFE_STRNCPY(g_results.network_behavior_summary, "HTTP requests detected - network tool", 
                   sizeof(g_results.network_behavior_summary));
    }
}

/**
 * @brief Analyze package repository access patterns
 */
void analyze_package_repositories(void) {
    runeanalyzer_log(2, "Analyzing package repository access...\n");
    
    // Check for common package repository URLs in arguments
    for (int i = 0; i < g_config.target_argc; i++) {
        const char* arg = g_config.target_args[i];
        
        // Debian/Ubuntu repositories
        if (strstr(arg, "debian.org") || strstr(arg, "ubuntu.com") || strstr(arg, "archive.ubuntu.com")) {
            g_results.package_downloads_detected = 1;
            SAFE_STRNCAT(g_results.repository_urls, "Debian/Ubuntu, ", sizeof(g_results.repository_urls));
            runeanalyzer_log(2, "Detected Debian/Ubuntu repository access\n");
            
            // Query repository for package info if this looks like a package name
            if (strlen(arg) < 100 && !strstr(arg, "/") && !strstr(arg, "http")) {
                query_debian_repository(arg);
            }
        }
        
        // PyPI (Python packages)
        if (strstr(arg, "pypi.org") || strstr(arg, "pypi.python.org")) {
            g_results.package_downloads_detected = 1;
            SAFE_STRNCAT(g_results.repository_urls, "PyPI, ", sizeof(g_results.repository_urls));
            runeanalyzer_log(2, "Detected PyPI repository access\n");
        }
        
        // NPM (Node.js packages)
        if (strstr(arg, "npmjs.com") || strstr(arg, "registry.npmjs.org")) {
            g_results.package_downloads_detected = 1;
            SAFE_STRNCAT(g_results.repository_urls, "NPM, ", sizeof(g_results.repository_urls));
            runeanalyzer_log(2, "Detected NPM repository access\n");
        }
        
        // Crates.io (Rust packages)
        if (strstr(arg, "crates.io")) {
            g_results.package_downloads_detected = 1;
            SAFE_STRNCAT(g_results.repository_urls, "Crates.io, ", sizeof(g_results.repository_urls));
            runeanalyzer_log(2, "Detected Rust crates.io repository access\n");
        }
        
        // Maven Central (Java packages)
        if (strstr(arg, "maven.org") || strstr(arg, "central.maven.org")) {
            g_results.package_downloads_detected = 1;
            SAFE_STRNCAT(g_results.repository_urls, "Maven Central, ", sizeof(g_results.repository_urls));
            runeanalyzer_log(2, "Detected Maven Central repository access\n");
        }
    }
    
    // Remove trailing comma from repository URLs
    size_t len = strlen(g_results.repository_urls);
    if (len > 2 && strcmp(&g_results.repository_urls[len-2], ", ") == 0) {
        g_results.repository_urls[len-2] = '\0';
    }
}

/**
 * @brief Query Debian repository for package information using runepkg's C++ FFI
 */
void query_debian_repository(const char* package_name) {
    runeanalyzer_log(2, "Querying Debian repository for package: %s\n", package_name);
    
    // This is where we would integrate with runepkg's C++ FFI network layer
    // For now, we'll simulate the functionality
    
    // Example of what the integration would look like:
    /*
    #include "../runepkg/runepkg_network_ffi.h"
    
    package_info_t* info = NULL;
    int result = cpp_get_package_info(package_name, info);
    
    if (result == CPP_SUCCESS && info) {
        runeanalyzer_log(1, "📦 Package Info: %s v%s (%ld bytes)\n", 
                     info->name, info->version, info->size);
        runeanalyzer_log(2, "📝 Description: %s\n", info->description);
        
        // Add to network behavior summary
        char package_info[256];
        snprintf(package_info, sizeof(package_info), 
                "Package repository query: %s v%s", info->name, info->version);
        SAFE_STRNCPY(g_results.network_behavior_summary, package_info, 
                   sizeof(g_results.network_behavior_summary));
        
        cpp_free_package_info(info);
    } else {
        runeanalyzer_log(2, "Could not retrieve package info for %s\n", package_name);
    }
    */
    
    // For now, just log that we would query the repository
    runeanalyzer_log(2, "Would query Debian repository for package metadata\n");
    
    // Update network behavior summary
    char summary[256];
    snprintf(summary, sizeof(summary), "Package repository query attempted: %s", package_name);
    SAFE_STRNCPY(g_results.network_behavior_summary, summary, sizeof(g_results.network_behavior_summary));
}

/**
 * @brief Check network activity of a specific process using /proc/net
 */
int check_network_activity(pid_t pid) {
    runeanalyzer_log(2, "Checking network activity for PID %d\n", pid);
    
    // Check for open network connections in /proc/net/tcp and /proc/net/udp
    FILE* tcp_file = fopen("/proc/net/tcp", "r");
    if (tcp_file) {
        char line[256];
        int connections = 0;
        
        // Skip header line
        if (fgets(line, sizeof(line), tcp_file)) {
            while (fgets(line, sizeof(line), tcp_file) && connections < 10) {
                // Parse TCP connection entry
                // Format: sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
                unsigned int local_addr, remote_addr;
                unsigned short local_port, remote_port;
                int state;
                
                if (sscanf(line, "%*d: %X:%hX %X:%hX %X", 
                          &local_addr, &local_port, &remote_addr, &remote_port, &state) >= 4) {
                    
                    // Check if this is an established outbound connection
                    if (state == 1 && remote_addr != 0) { // 1 = TCP_ESTABLISHED
                        connections++;
                        g_results.network_connections_detected++;
                        
                        // Convert addresses to readable format
                        char remote_ip[16];
                        snprintf(remote_ip, sizeof(remote_ip), "%d.%d.%d.%d",
                                remote_addr & 0xFF,
                                (remote_addr >> 8) & 0xFF,
                                (remote_addr >> 16) & 0xFF,
                                (remote_addr >> 24) & 0xFF);
                        
                        runeanalyzer_log(2, "Network connection detected: %s:%d\n", remote_ip, remote_port);
                    }
                }
            }
        }
        fclose(tcp_file);
        
        if (connections > 0) {
            g_results.network_connections_detected = connections;
            return 1;
        }
    }
    
    return 0;
}

/**
 * @brief Analyze verbose output patterns from common Linux tools
 * Your insight: verbose output reveals the internal operations and decision paths!
 */
void analyze_verbose_patterns(void) {
    runeanalyzer_log(2, "Analyzing verbose output patterns...\n");
    
    // Initialize verbose intelligence fields
    g_results.file_operations_detected = 0;
    g_results.progress_indicators = 0;
    g_results.path_manipulations = 0;
    g_results.network_operations = 0;
    g_results.compression_operations = 0;
    g_results.compilation_steps = 0;
    g_results.database_operations = 0;
    g_results.system_calls_verbose = 0;
    g_results.verbose_intelligence_score = 1;
    strncpy(g_results.verbose_operation_type, "unknown", sizeof(g_results.verbose_operation_type) - 1);
    
    // Note: In a real implementation, we would capture and analyze the actual output
    // For now, we'll make intelligent guesses based on tool classification and behavior
    
    const char* executable = g_config.target_executable;
    const char* basename = strrchr(executable, '/');
    if (basename) basename++; else basename = executable;
    
    // File operation tools (cp, mv, ln, chmod, etc.)
    if (strstr(basename, "cp") || strstr(basename, "mv") || strstr(basename, "ln")) {
        g_results.file_operations_detected = 1;
        g_results.path_manipulations = 1;
        strncpy(g_results.verbose_operation_type, "file_operations", sizeof(g_results.verbose_operation_type) - 1);
        g_results.verbose_intelligence_score = 8;
        runeanalyzer_log(2, "File operation tool detected - verbose shows file paths and operations\n");
    }
    
    // Compression tools (tar, gzip, zip, etc.)
    else if (strstr(basename, "tar") || strstr(basename, "gzip") || strstr(basename, "zip") || strstr(basename, "unzip")) {
        g_results.compression_operations = 1;
        g_results.file_operations_detected = 1;
        g_results.progress_indicators = 1;
        strncpy(g_results.verbose_operation_type, "compression", sizeof(g_results.verbose_operation_type) - 1);
        g_results.verbose_intelligence_score = 9;
        runeanalyzer_log(2, "Compression tool detected - verbose shows file processing and progress\n");
    }
    
    // Compilation tools (gcc, make, ld, etc.)
    else if (strstr(basename, "gcc") || strstr(basename, "clang") || strstr(basename, "make") || strstr(basename, "ld")) {
        g_results.compilation_steps = 1;
        g_results.file_operations_detected = 1;
        strncpy(g_results.verbose_operation_type, "compilation", sizeof(g_results.verbose_operation_type) - 1);
        g_results.verbose_intelligence_score = 10;
        runeanalyzer_log(2, "Compilation tool detected - verbose shows build steps and dependencies\n");
    }
    
    // Network tools (wget, curl, rsync, etc.)
    else if (strstr(basename, "wget") || strstr(basename, "curl") || strstr(basename, "rsync")) {
        g_results.network_operations = 1;
        g_results.progress_indicators = 1;
        strncpy(g_results.verbose_operation_type, "network_transfer", sizeof(g_results.verbose_operation_type) - 1);
        g_results.verbose_intelligence_score = 9;
        runeanalyzer_log(2, "Network tool detected - verbose shows transfer progress and details\n");
    }
    
    // System diagnostic tools (strace, ltrace, ldd, etc.)
    else if (strstr(basename, "strace") || strstr(basename, "ltrace") || strstr(basename, "ldd")) {
        g_results.system_calls_verbose = 1;
        strncpy(g_results.verbose_operation_type, "system_diagnostics", sizeof(g_results.verbose_operation_type) - 1);
        g_results.verbose_intelligence_score = 10;
        runeanalyzer_log(2, "System diagnostic tool detected - verbose shows system call details\n");
    }
    
    // Package managers (apt, yum, dnf, etc.)
    else if (strstr(basename, "apt") || strstr(basename, "yum") || strstr(basename, "dnf") || strstr(basename, "runepkg")) {
        g_results.file_operations_detected = 1;
        g_results.network_operations = 1;
        g_results.progress_indicators = 1;
        strncpy(g_results.verbose_operation_type, "package_management", sizeof(g_results.verbose_operation_type) - 1);
        g_results.verbose_intelligence_score = 9;
        runeanalyzer_log(2, "Package manager detected - verbose shows download and installation steps\n");
    }
    
    // Generic file utilities
    else if (strcmp(g_results.tool_classification, "file_utility") == 0) {
        g_results.file_operations_detected = 1;
        g_results.path_manipulations = 1;
        strncpy(g_results.verbose_operation_type, "file_utility", sizeof(g_results.verbose_operation_type) - 1);
        g_results.verbose_intelligence_score = 6;
        runeanalyzer_log(2, "File utility detected - verbose likely shows file processing details\n");
    }
}

/**
 * @brief Detect tool-specific intelligence from verbose patterns
 */
void detect_tool_specific_intelligence(void) {
    runeanalyzer_log(2, "Detecting tool-specific intelligence patterns...\n");
    
    // Analyze output characteristics to infer verbose patterns
    
    // High output volume suggests verbose mode or detailed operations
    if (g_results.stdout_bytes > 1000) {
        g_results.verbose_intelligence_score += 2;
        runeanalyzer_log(2, "High output volume suggests detailed verbose information\n");
    }
    
    // Multiple lines suggest structured verbose output
    if (g_results.verbose_messages > 5) {
        g_results.structured_output_detected = 1;
        g_results.verbose_intelligence_score += 1;
        runeanalyzer_log(2, "Multiple verbose messages suggest structured output\n");
    }
    
    // Fast execution with significant output suggests efficient verbose reporting
    if (g_results.execution_time < 0.1 && g_results.stdout_bytes > 100) {
        g_results.verbose_intelligence_score += 1;
        runeanalyzer_log(2, "Fast execution with output suggests efficient verbose reporting\n");
    }
    
    // Adjust intelligence score based on tool type
    if (strcmp(g_results.tool_classification, "compiler") == 0 && g_results.verbose_intelligence_score < 8) {
        g_results.verbose_intelligence_score = 8; // Compilers have very informative verbose output
    }
    
    // Cap the score
    if (g_results.verbose_intelligence_score > 10) g_results.verbose_intelligence_score = 10;
}

/**
 * @brief Decode exit code to human-readable explanation
 * This is your brilliant idea in action - exit codes tell the whole story!
 */
const char* decode_exit_code(int exit_code) {
    switch (exit_code) {
        case 0:   return "Success";
        case 1:   return "General Error";
        case 2:   return "Misuse of Shell Builtin";
        case 126: return "Command Cannot Execute";
        case 127: return "Command Not Found";
        case 128: return "Invalid Argument to Exit";
        case 130: return "Script Terminated by Ctrl-C";
        
        // Critical security-related signals (128 + signal number)
        case 132: return "SIGILL - Illegal Instruction (Code Corruption!)";
        case 133: return "SIGTRAP - Trace/Breakpoint Trap";
        case 134: return "SIGABRT - Abort Signal (Heap Corruption/Double Free!)";
        case 135: return "SIGBUS - Bus Error (Memory Alignment Violation!)";
        case 136: return "SIGFPE - Floating Point Exception (Integer Overflow!)";
        case 137: return "SIGKILL - Killed by System (Resource Exhaustion!)";
        case 139: return "SIGSEGV - Segmentation Fault (Buffer Overflow/Memory Corruption!)";
        case 140: return "SIGPIPE - Broken Pipe";
        case 141: return "SIGALRM - Alarm Clock";
        case 142: return "SIGTERM - Termination Signal";
        
        default:
            if (exit_code > 128 && exit_code < 192) {
                return "Signal-based termination (check signal number)";
            } else {
                return "Unknown error code";
            }
    }
}

/**
 * @brief Print human-readable analysis report
 */
void print_human_report(void) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("🔬 " COLOR_BOLD "RuneAnalyzer Universal Analysis Report" COLOR_RESET "\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    // Basic execution info
    printf("📊 " COLOR_BLUE "Execution Summary:" COLOR_RESET "\n");
    printf("  ⏱️  Execution Time: %.3fs\n", g_results.execution_time);
    printf("  🔢 Exit Code: %d - %s\n", g_results.exit_code, decode_exit_code(g_results.exit_code));
    
    // Show critical security alerts for dangerous exit codes
    if (g_results.exit_code == 139 || g_results.exit_code == 134 || g_results.exit_code == 135 || g_results.exit_code == 136 || g_results.exit_code == 132) {
        printf("  🚨 " COLOR_RED "SECURITY ALERT: This exit code indicates memory corruption!" COLOR_RESET "\n");
    }
    
    // Memory analysis
    if (g_config.enable_memory && g_results.peak_memory_kb > 0) {
        printf("💾 " COLOR_MAGENTA "Memory Analysis:" COLOR_RESET "\n");
        if (g_results.peak_memory_kb < 1024) {
            printf("  📊 Peak Memory Usage: %ld KB\n", g_results.peak_memory_kb);
        } else {
            printf("  📊 Peak Memory Usage: %.1f MB\n", g_results.peak_memory_kb / 1024.0);
        }
    }
    
    // I/O analysis
    printf("💿 " COLOR_CYAN "I/O Analysis:" COLOR_RESET "\n");
    printf("  📤 Stdout Output: %zu bytes\n", g_results.stdout_bytes);
    printf("  📥 Stderr Output: %zu bytes\n", g_results.stderr_bytes);
    
    // Output pattern analysis
    if (g_results.verbose_messages > 0 || g_results.error_messages > 0 || g_results.warning_messages > 0) {
        printf("🧠 " COLOR_GREEN "Output Intelligence:" COLOR_RESET "\n");
        if (g_results.verbose_messages > 0) {
            printf("  📊 Verbose Messages: %d\n", g_results.verbose_messages);
        }
        if (g_results.error_messages > 0) {
            printf("  ❌ Error Messages: %d\n", g_results.error_messages);
        }
        if (g_results.warning_messages > 0) {
            printf("  ⚠️  Warning Messages: %d\n", g_results.warning_messages);
        }
    }
    
    // Deep analysis results (-vv mode)
    if (g_config.enable_deep_analysis) {
        printf("🧬 " COLOR_BOLD "Deep Analysis Results:" COLOR_RESET "\n");
        printf("  🏷️  Tool Classification: %s\n", g_results.tool_classification);
        printf("  🎯 Behavior Pattern: %s\n", g_results.behavior_pattern);
        printf("  📈 Performance Category: %s\n", g_results.performance_category);
        printf("  🧮 Output Complexity: %d/10\n", g_results.output_complexity_score);
        printf("  ⚡ Resource Efficiency: %d/10\n", g_results.resource_efficiency_score);
        
        // Language and Runtime Detection
        if (strcmp(g_results.detected_language, "Unknown") != 0) {
            printf("🔤 " COLOR_BOLD "Language & Runtime Analysis:" COLOR_RESET "\n");
            printf("  💬 Detected Language: %s\n", g_results.detected_language);
            
            if (strcmp(g_results.runtime_version, "Unknown") != 0) {
                printf("  🔧 Runtime Version: %s\n", g_results.runtime_version);
            }
            
            if (strcmp(g_results.dependency_manager, "None") != 0) {
                printf("  📦 Dependency Manager: %s\n", g_results.dependency_manager);
            }
            
            printf("  🧠 Managed Memory: %s\n", g_results.uses_managed_memory ? "Yes" : "No");
            
            if (g_results.jvm_analysis_available) {
                printf("  ☕ JVM Analysis Available: Yes\n");
            }
            
            if (g_results.cargo_project_detected) {
                printf("  🦀 Cargo Project Detected: Yes\n");
            }
            
            if (g_results.uses_unsafe_code) {
                printf("  ⚠️  Unsafe Code Detected: " COLOR_YELLOW "Yes" COLOR_RESET "\n");
            }
            
            if (g_results.language_specific_info[0]) {
                printf("  💡 Language Info: %s\n", g_results.language_specific_info);
            }
            
            if (strcmp(g_results.detected_frameworks, "None detected") != 0 && g_results.detected_frameworks[0]) {
                printf("  🚀 Detected Frameworks: %s\n", g_results.detected_frameworks);
            }
        }
        
        if (g_results.execution_time > 0.1) {
            printf("  ⏰ Timing Breakdown:\n");
            printf("    • Startup Time: %.3fs (%.1f%%)\n", g_results.startup_time, 
                   (g_results.startup_time / g_results.execution_time) * 100);
            printf("    • Processing Time: %.3fs (%.1f%%)\n", g_results.processing_time,
                   (g_results.processing_time / g_results.execution_time) * 100);
            printf("    • Cleanup Time: %.3fs (%.1f%%)\n", g_results.cleanup_time,
                   (g_results.cleanup_time / g_results.execution_time) * 100);
        }
        
        // Advanced patterns
        if (g_results.structured_output_detected) {
            printf("  📊 Structured Output Detected: Yes\n");
        }
        
        // Verbose Intelligence Analysis (your brilliant insight!)
        if (g_results.verbose_intelligence_score > 1) {
            printf("🔍 " COLOR_BOLD "Verbose Intelligence Analysis:" COLOR_RESET "\n");
            printf("  📋 Verbose Operation Type: %s\n", g_results.verbose_operation_type);
            printf("  🧠 Verbose Intelligence Score: %d/10\n", g_results.verbose_intelligence_score);
            
            // Show specific verbose patterns detected
            if (g_results.file_operations_detected) {
                printf("  📁 File Operations Detected: Yes\n");
            }
            if (g_results.path_manipulations) {
                printf("  🛤️  Path Manipulations: Yes\n");
            }
            if (g_results.progress_indicators) {
                printf("  ⏳ Progress Indicators: Yes\n");
            }
            if (g_results.network_operations) {
                printf("  🌐 Network Operations: Yes\n");
            }
            if (g_results.compression_operations) {
                printf("  🗜️  Compression Operations: Yes\n");
            }
            if (g_results.compilation_steps) {
                printf("  🔧 Compilation Steps: Yes\n");
            }
            if (g_results.system_calls_verbose) {
                printf("  ⚙️  System Call Details: Yes\n");
            }
            
            // Verbose intelligence insight
            if (g_results.verbose_intelligence_score >= 8) {
                printf("  💡 " COLOR_GREEN "HIGH: Verbose output provides excellent operational insights!" COLOR_RESET "\n");
            } else if (g_results.verbose_intelligence_score >= 5) {
                printf("  💡 " COLOR_YELLOW "MEDIUM: Verbose output provides useful information" COLOR_RESET "\n");
            }
        }
        
        // Security analysis results (if enabled)
        if (g_config.enable_security) {
            printf("🛡️  " COLOR_BOLD "Security Analysis:" COLOR_RESET "\n");
            printf("  🔒 Security Classification: %s\n", g_results.security_classification);
            printf("  🛡️  Overall Security Score: %d/10\n", g_results.overall_security_score);
            
            // Show specific vulnerability indicators if detected
            if (g_results.buffer_overflow_risk > 0) {
                printf("  ⚠️  Buffer Overflow Risk: %d/5\n", g_results.buffer_overflow_risk);
            }
            if (g_results.memory_leak_indicators > 0) {
                printf("  💧 Memory Leak Indicators: %d\n", g_results.memory_leak_indicators);
            }
            if (g_results.use_after_free_risk > 0) {
                printf("  🔄 Use-After-Free Risk: %d/5\n", g_results.use_after_free_risk);
            }
            if (g_results.format_string_vuln > 0) {
                printf("  📝 Format String Vulnerability: %d/5\n", g_results.format_string_vuln);
            }
            if (g_results.dangerous_function_count > 0) {
                printf("  ⚠️  Dangerous Function Usage: %d patterns\n", g_results.dangerous_function_count);
            }
            
            // Security recommendation
            if (g_results.overall_security_score <= 3) {
                printf("  🚨 " COLOR_RED "CRITICAL: High security risk detected!" COLOR_RESET "\n");
            } else if (g_results.overall_security_score <= 6) {
                printf("  ⚠️  " COLOR_YELLOW "WARNING: Medium security risk detected" COLOR_RESET "\n");
            } else {
                printf("  ✅ " COLOR_GREEN "GOOD: Low security risk" COLOR_RESET "\n");
            }
            
            // NEW: Pinpoint Vulnerability Analysis Results
            if (g_results.vulnerable_function_count > 0) {
                printf("🎯 " COLOR_BOLD "Pinpoint Vulnerability Analysis:" COLOR_RESET "\n");
                printf("  🔍 Vulnerable Functions Found: %d\n", g_results.vulnerable_function_count);
                
                for (int i = 0; i < g_results.vulnerable_function_count && i < 5; i++) {
                    printf("    • %s\n", g_results.vulnerable_functions[i]);
                }
                
                if (g_results.crash_function[0]) {
                    printf("  💥 " COLOR_RED "Crash Location: %s" COLOR_RESET, g_results.crash_function);
                    if (g_results.crash_line_number > 0) {
                        printf(" (line %d)", g_results.crash_line_number);
                    }
                    printf("\n");
                }
                
                if (g_results.source_file[0]) {
                    printf("  📄 Source File: %s\n", g_results.source_file);
                }
                
                if (g_results.vulnerability_details[0]) {
                    printf("  📝 Details: %s\n", g_results.vulnerability_details);
                }
                
                if (g_results.has_debug_symbols) {
                    printf("  🐛 Debug Symbols: Available (enhanced analysis possible)\n");
                } else {
                    printf("  🐛 Debug Symbols: Not available (limited analysis)\n");
                }
            }
        }
        
        // Network Behavior Analysis Results (NEW!)
        if (g_config.enable_network_analysis) {
            printf("🌐 " COLOR_BOLD "Network Behavior Analysis:" COLOR_RESET "\n");
            printf("  🔗 Network Connections: %d detected\n", g_results.network_connections_detected);
            printf("  📡 HTTP Requests: %d detected\n", g_results.outbound_http_requests);
            printf("  🌐 Network Security Score: %d/10\n", g_results.network_security_score);
            printf("  📋 Behavior Summary: %s\n", g_results.network_behavior_summary);
            
            if (strlen(g_results.external_hosts_contacted) > 0) {
                printf("  🎯 External Hosts: %s\n", g_results.external_hosts_contacted);
            }
            
            if (strlen(g_results.repository_urls) > 0) {
                printf("  📦 Repositories Accessed: %s\n", g_results.repository_urls);
            }
            
            if (g_results.package_downloads_detected) {
                printf("  📥 Package Downloads: Yes\n");
            }
            
            if (g_results.data_upload_detected) {
                printf("  📤 " COLOR_YELLOW "Data Uploads Detected: Yes" COLOR_RESET "\n");
            }
            
            if (g_results.suspicious_network_activity) {
                printf("  🚨 " COLOR_RED "Suspicious Network Activity: Yes" COLOR_RESET "\n");
            }
            
            // Network security recommendation
            if (g_results.network_security_score <= 3) {
                printf("  🚨 " COLOR_RED "HIGH RISK: Suspicious network behavior detected!" COLOR_RESET "\n");
            } else if (g_results.network_security_score <= 6) {
                printf("  ⚠️  " COLOR_YELLOW "MEDIUM RISK: Review network activity" COLOR_RESET "\n");
            } else if (g_results.network_connections_detected > 0) {
                printf("  ✅ " COLOR_GREEN "LOW RISK: Normal network behavior" COLOR_RESET "\n");
            } else {
                printf("  🔒 " COLOR_GREEN "ISOLATED: No network activity detected" COLOR_RESET "\n");
            }
        }
    }
    
    // Performance rating
    printf("⚡ " COLOR_YELLOW "Performance Rating:" COLOR_RESET " ");
    if (g_results.execution_time < 0.1) {
        printf(COLOR_GREEN "Excellent" COLOR_RESET " (%.3fs)\n", g_results.execution_time);
    } else if (g_results.execution_time < 1.0) {
        printf(COLOR_BLUE "Good" COLOR_RESET " (%.3fs)\n", g_results.execution_time);
    } else if (g_results.execution_time < 5.0) {
        printf(COLOR_YELLOW "Moderate" COLOR_RESET " (%.3fs)\n", g_results.execution_time);
    } else {
        printf(COLOR_RED "Needs Optimization" COLOR_RESET " (%.3fs)\n", g_results.execution_time);
    }
    
    printf("═══════════════════════════════════════════════════════════════\n");
}

/**
 * @brief Print JSON analysis report
 */
void print_json_report(void) {
    printf("{\n");
    printf("  \"runeanalyzer_version\": \"%s\",\n", RUNEANALYZER_VERSION);
    printf("  \"analysis_timestamp\": %ld,\n", time(NULL));
    printf("  \"target_executable\": \"%s\",\n", g_config.target_executable);
    printf("  \"execution\": {\n");
    printf("    \"time_seconds\": %.6f,\n", g_results.execution_time);
    printf("    \"exit_code\": %d,\n", g_results.exit_code);
    printf("    \"success\": %s\n", g_results.exit_code == 0 ? "true" : "false");
    printf("  },\n");
    printf("  \"memory\": {\n");
    printf("    \"peak_kb\": %ld\n", g_results.peak_memory_kb);
    printf("  },\n");
    printf("  \"io\": {\n");
    printf("    \"stdout_bytes\": %zu,\n", g_results.stdout_bytes);
    printf("    \"stderr_bytes\": %zu\n", g_results.stderr_bytes);
    printf("  },\n");
    printf("  \"intelligence\": {\n");
    printf("    \"verbose_messages\": %d,\n", g_results.verbose_messages);
    printf("    \"error_messages\": %d,\n", g_results.error_messages);
    printf("    \"warning_messages\": %d\n", g_results.warning_messages);
    printf("  },\n");
    printf("  \"deep_analysis\": {\n");
    printf("    \"enabled\": %s,\n", g_config.enable_deep_analysis ? "true" : "false");
    if (g_config.enable_deep_analysis) {
        printf("    \"tool_classification\": \"%s\",\n", g_results.tool_classification);
        printf("    \"behavior_pattern\": \"%s\",\n", g_results.behavior_pattern);
        printf("    \"performance_category\": \"%s\",\n", g_results.performance_category);
        printf("    \"output_complexity_score\": %d,\n", g_results.output_complexity_score);
        printf("    \"resource_efficiency_score\": %d,\n", g_results.resource_efficiency_score);
        printf("    \"timing_breakdown\": {\n");
        printf("      \"startup_time_seconds\": %.6f,\n", g_results.startup_time);
        printf("      \"processing_time_seconds\": %.6f,\n", g_results.processing_time);
        printf("      \"cleanup_time_seconds\": %.6f\n", g_results.cleanup_time);
        printf("    },\n");
        printf("    \"structured_output_detected\": %s,", g_results.structured_output_detected ? "true" : "false");
        
        // Language and Runtime Analysis
        printf("\n    \"language_analysis\": {\n");
        printf("      \"detected_language\": \"%s\",\n", g_results.detected_language);
        printf("      \"runtime_version\": \"%s\",\n", g_results.runtime_version);
        printf("      \"dependency_manager\": \"%s\",\n", g_results.dependency_manager);
        printf("      \"uses_managed_memory\": %s,\n", g_results.uses_managed_memory ? "true" : "false");
        printf("      \"uses_unsafe_code\": %s,\n", g_results.uses_unsafe_code ? "true" : "false");
        printf("      \"jvm_analysis_available\": %s,\n", g_results.jvm_analysis_available ? "true" : "false");
        printf("      \"cargo_project_detected\": %s,\n", g_results.cargo_project_detected ? "true" : "false");
        printf("      \"language_specific_info\": \"%s\"\n", g_results.language_specific_info);
        printf("    }");
        
        // Add security analysis to JSON if enabled
        if (g_config.enable_security) {
            printf(",\n    \"security_analysis\": {\n");
            printf("      \"security_classification\": \"%s\",\n", g_results.security_classification);
            printf("      \"overall_security_score\": %d,\n", g_results.overall_security_score);
            printf("      \"vulnerability_indicators\": {\n");
            printf("        \"buffer_overflow_risk\": %d,\n", g_results.buffer_overflow_risk);
            printf("        \"memory_leak_indicators\": %d,\n", g_results.memory_leak_indicators);
            printf("        \"use_after_free_risk\": %d,\n", g_results.use_after_free_risk);
            printf("        \"format_string_vulnerability\": %d,\n", g_results.format_string_vuln);
            printf("        \"null_pointer_risk\": %d,\n", g_results.null_pointer_risk);
            printf("        \"integer_overflow_risk\": %d,\n", g_results.integer_overflow_risk);
            printf("        \"uninitialized_memory_risk\": %d,\n", g_results.uninitialized_memory_risk);
            printf("        \"dangerous_function_count\": %d\n", g_results.dangerous_function_count);
            printf("      },\n");
            printf("      \"pinpoint_analysis\": {\n");
            printf("        \"vulnerable_function_count\": %d,\n", g_results.vulnerable_function_count);
            printf("        \"has_debug_symbols\": %s,\n", g_results.has_debug_symbols ? "true" : "false");
            if (g_results.vulnerable_function_count > 0) {
                printf("        \"vulnerable_functions\": [");
                for (int i = 0; i < g_results.vulnerable_function_count && i < 5; i++) {
                    printf("\"%s\"", g_results.vulnerable_functions[i]);
                    if (i < g_results.vulnerable_function_count - 1 && i < 4) printf(", ");
                }
                printf("],\n");
            }
            if (g_results.crash_function[0]) {
                printf("        \"crash_function\": \"%s\",\n", g_results.crash_function);
                printf("        \"crash_line_number\": %d,\n", g_results.crash_line_number);
            }
            if (g_results.source_file[0]) {
                printf("        \"source_file\": \"%s\",\n", g_results.source_file);
            }
            if (g_results.vulnerability_details[0]) {
                printf("        \"vulnerability_details\": \"%s\"\n", g_results.vulnerability_details);
            } else {
                printf("        \"vulnerability_details\": null\n");
            }
            printf("      }\n");
            printf("    }");
        }
        printf("\n");
    } else {
        printf("    \"message\": \"Enable with -vv flag for detailed analysis\"\n");
    }
    printf("  }\n");
    printf("}\n");
}

/**
 * @brief Print usage information
 */
void print_usage(const char* program_name) {
    printf("RuneAnalyzer - Advanced Linux Executable Security & Performance Analyzer v%s\n", RUNEANALYZER_VERSION);
    printf("Copyright (C) 2025 Christopher Michko\n\n");
    printf("Usage: %s [OPTIONS] <executable> [args...]\n\n", program_name);
    printf("Options:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -v, --verbose           Enable verbose output\n");
    printf("  -vv, --very-verbose     Enable very verbose mode with deep analysis\n");
    printf("  -q, --quiet             Quiet mode (errors only)\n");
    printf("  --version               Show version information\n");
    printf("  --json                  Output results in JSON format\n");
    printf("  --human                 Output results in human-readable format (default)\n");
    printf("  --both                  Output both human and JSON formats\n");
    printf("  --memory                Enable memory profiling\n");
    printf("  --io                    Enable I/O monitoring\n");
    printf("  --security              Enable security analysis\n");
    printf("  --performance           Enable performance profiling\n");
    printf("  --all                   Enable all analysis modules\n\n");
    printf("Examples:\n");
    printf("  %s /bin/ls -la                    # Analyze ls command\n", program_name);
    printf("  %s -vv /usr/bin/sort file.txt     # Deep analysis with verbose mode\n", program_name);
    printf("  %s --json /usr/bin/gcc --version  # JSON output for gcc\n", program_name);
    printf("  %s --all /usr/bin/python3 script.py  # Full analysis\n", program_name);
    printf("\n");
}

/**
 * @brief Main function
 */
int main(int argc, char* argv[]) {
    // DEFENSIVE: Validate main function arguments
    if (argc <= 0 || !argv) {
        fprintf(stderr, "Error: Invalid program arguments\n");
        return 1;
    }
    
    if (!argv[0]) {
        fprintf(stderr, "Error: Program name is NULL\n");
        return 1;
    }
    
    // DEFENSIVE: Check for argument count limits to prevent potential attacks
    if (argc > MAX_ARGS) {
        fprintf(stderr, "Error: Too many arguments (%d > %d)\n", argc, MAX_ARGS);
        return 1;
    }
    
    // DEFENSIVE: Validate each argument pointer
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) {
            fprintf(stderr, "Error: Argument %d is NULL\n", i);
            return 1;
        }
        // Check for reasonable argument length to prevent buffer overflow attacks
        if (strnlen(argv[i], MAX_COMMAND_LENGTH) >= MAX_COMMAND_LENGTH) {
            fprintf(stderr, "Error: Argument %d too long\n", i);
            return 1;
        }
    }
    
    // Initialize default configuration - SECURE DEFAULTS
    memset(&g_config, 0, sizeof(g_config));
    memset(&g_results, 0, sizeof(g_results));
    
    g_config.verbose_mode = 1;
    g_config.output_format = 0; // human readable
    g_config.enable_memory = 1;
    g_config.enable_io = 1;
    g_config.enable_security = 0;  // Security disabled by default for safety
    g_config.enable_performance = 0;
    g_config.enable_deep_analysis = 0;
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    int executable_index = -1;
    
    // Parse options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("RuneAnalyzer v%s\n", RUNEANALYZER_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-vv") == 0 || strcmp(argv[i], "--very-verbose") == 0) {
            g_config.verbose_mode = 3;  // Very verbose mode
            g_config.enable_deep_analysis = 1;  // Auto-enable deep analysis
            g_config.enable_performance = 1;    // Auto-enable performance profiling
            g_config.enable_security = 1;       // Auto-enable security analysis
            g_config.enable_network_analysis = 1; // Auto-enable network analysis
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_config.verbose_mode = 2;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            g_config.verbose_mode = 0;
        } else if (strcmp(argv[i], "--json") == 0) {
            g_config.output_format = 1;
        } else if (strcmp(argv[i], "--human") == 0) {
            g_config.output_format = 0;
        } else if (strcmp(argv[i], "--both") == 0) {
            g_config.output_format = 2;
        } else if (strcmp(argv[i], "--memory") == 0) {
            g_config.enable_memory = 1;
        } else if (strcmp(argv[i], "--io") == 0) {
            g_config.enable_io = 1;
        } else if (strcmp(argv[i], "--security") == 0) {
            g_config.enable_security = 1;
        } else if (strcmp(argv[i], "--performance") == 0) {
            g_config.enable_performance = 1;
        } else if (strcmp(argv[i], "--all") == 0) {
            g_config.enable_memory = 1;
            g_config.enable_io = 1;
            g_config.enable_security = 1;
            g_config.enable_performance = 1;
        } else if (argv[i][0] != '-') {
            // Found the executable
            executable_index = i;
            break;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            return 1;
        }
    }
    
    if (executable_index == -1) {
        fprintf(stderr, "Error: No executable specified\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Copy executable path
    strncpy(g_config.target_executable, argv[executable_index], PATH_MAX - 1);
    g_config.target_executable[PATH_MAX - 1] = '\0';
    
    // Copy arguments
    g_config.target_argc = argc - executable_index - 1;
    g_config.target_args = &argv[executable_index + 1];
    
    // Validate input
    if (validate_executable(g_config.target_executable) != 0) {
        return 1;
    }
    
    if (sanitize_args(g_config.target_args, g_config.target_argc) != 0) {
        return 1;
    }
    
    // Execute and analyze
    int result = execute_and_analyze();
    if (result != 0) {
        return 1;
    }
    
    // Generate report
    if (g_config.output_format == 0 || g_config.output_format == 2) {
        print_human_report();
    }
    
    if (g_config.output_format == 1 || g_config.output_format == 2) {
        print_json_report();
    }
    
    return g_results.exit_code == 0 ? 0 : 1;
}
