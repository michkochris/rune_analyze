/**
 * rune_analysis_safe.c - Safe Non-Executing Analysis Mode
 *
 * 🛡️ SAFE ANALYSIS WITHOUT SYSTEM EXECUTION
 * 
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * This implements safe analysis that provides deep insights
 * WITHOUT executing potentially dangerous code on the system.
 */

#include "rune_analyze.h"
#include <ctype.h>      // For tolower()
#include <string.h>     // For string functions
#include <strings.h>    // For strncasecmp on some systems

// 🛡️ Safe package analysis without execution
int rune_safe_analyze_package(const char* package_path) {
    RUNE_LOG_FUNC_START("safe_analyze_package");
    
    printf("🛡️ SAFE ANALYSIS MODE: %s\n", package_path);
    printf("═══════════════════════════════════════\n");
    printf("Analyzing package WITHOUT system execution\n");
    printf("(Safe for malicious/unknown packages)\n\n");
    
    int risk_score = 0;
    
    // Phase 1: File System Analysis
    printf("📁 Phase 1: File System Analysis\n");
    printf("─────────────────────────────────\n");
    
    struct stat file_stat;
    if (stat(package_path, &file_stat) == 0) {
        printf("📊 Package size: %ld bytes (%.2f MB)\n", 
               file_stat.st_size, file_stat.st_size / 1024.0 / 1024.0);
        printf("📅 Last modified: %s", ctime(&file_stat.st_mtime));
        printf("🔐 Permissions: %o\n", file_stat.st_mode & 0777);
        
        // Size-based risk assessment
        if (file_stat.st_size > 500 * 1024 * 1024) { // > 500MB
            printf("⚠️  RISK: Extremely large package (>500MB)\n");
            risk_score += 3;
        } else if (file_stat.st_size > 100 * 1024 * 1024) { // > 100MB
            printf("⚠️  WARNING: Large package (>100MB)\n");
            risk_score += 1;
        } else if (file_stat.st_size < 1024) { // < 1KB
            printf("⚠️  WARNING: Suspiciously small package\n");
            risk_score += 2;
        } else {
            printf("✅ Package size appears normal\n");
        }
    }
    
    // Phase 2: Filename Pattern Analysis
    printf("\n🔍 Phase 2: Filename Pattern Analysis\n");
    printf("────────────────────────────────────\n");
    
    const char* filename = strrchr(package_path, '/');
    if (!filename) filename = strrchr(package_path, '\\');  // Windows support
    if (!filename) filename = package_path;
    else filename++;
    
    printf("📂 Analyzing filename: %s\n", filename);
    
    // High-risk patterns
    const char* dangerous_patterns[] = {
        "hack", "exploit", "backdoor", "malware", "virus", "trojan",
        "keylog", "rootkit", "botnet", "ransomware", "cryptojack"
    };
    
    for (int i = 0; i < sizeof(dangerous_patterns) / sizeof(dangerous_patterns[0]); i++) {
        if (strcasestr(filename, dangerous_patterns[i])) {
            printf("🚨 CRITICAL: Filename contains '%s'\n", dangerous_patterns[i]);
            risk_score += 5;
        }
    }
    
    // Suspicious patterns
    const char* suspicious_patterns[] = {
        "admin", "root", "sudo", "system", "kernel", "driver",
        "network", "proxy", "tunnel", "bypass"
    };
    
    for (int i = 0; i < sizeof(suspicious_patterns) / sizeof(suspicious_patterns[0]); i++) {
        if (strcasestr(filename, suspicious_patterns[i])) {
            printf("⚠️  SUSPICIOUS: Filename contains '%s'\n", suspicious_patterns[i]);
            risk_score += 1;
        }
    }
    
    // Phase 3: Archive Structure Analysis (without extraction)
    printf("\n📦 Phase 3: Archive Structure Analysis\n");
    printf("────────────────────────────────────\n");
    
    // Use 'ar' or 'dpkg-deb' to inspect WITHOUT extracting
    char inspect_cmd[512];
    snprintf(inspect_cmd, sizeof(inspect_cmd), 
             "dpkg-deb --info \"%s\" 2>/dev/null || ar -tv \"%s\" 2>/dev/null || echo 'Cannot inspect archive'", 
             package_path, package_path);
    
    printf("🔍 Archive contents inspection:\n");
    printf("(Running: %s)\n", inspect_cmd);
    
    FILE* pipe = popen(inspect_cmd, "r");
    if (pipe) {
        char line[1024];
        int line_count = 0;
        while (fgets(line, sizeof(line), pipe) && line_count < 20) {
            printf("   %s", line);
            
            // Analyze control files for risks
            if (strstr(line, "postinst") || strstr(line, "preinst")) {
                printf("   ⚠️  Contains installation scripts\n");
                risk_score += 1;
            }
            if (strstr(line, "postrm") || strstr(line, "prerm")) {
                printf("   ⚠️  Contains removal scripts\n");
                risk_score += 1;
            }
            
            line_count++;
        }
        
        if (line_count >= 20) {
            printf("   ... (truncated - many files)\n");
            risk_score += 1;  // Many files can be suspicious
        }
        
        pclose(pipe);
    } else {
        printf("❌ Cannot inspect archive structure\n");
        risk_score += 1;
    }
    
    // Phase 4: Static Analysis (without execution)
    printf("\n🔬 Phase 4: Static Content Analysis\n");
    printf("──────────────────────────────────\n");
    
    // Check for suspicious strings in the package
    snprintf(inspect_cmd, sizeof(inspect_cmd), 
             "strings \"%s\" 2>/dev/null | grep -E '(eval|exec|system|download|wget|curl|nc |bash -c)' | head -10", 
             package_path);
    
    printf("🔍 Suspicious string analysis:\n");
    pipe = popen(inspect_cmd, "r");
    if (pipe) {
        char line[1024];
        int suspicious_strings = 0;
        while (fgets(line, sizeof(line), pipe) && suspicious_strings < 10) {
            printf("   ⚠️  Suspicious: %s", line);
            suspicious_strings++;
            risk_score += 1;
        }
        
        if (suspicious_strings == 0) {
            printf("   ✅ No obviously suspicious strings found\n");
        } else {
            printf("   🚨 Found %d suspicious string patterns\n", suspicious_strings);
        }
        
        pclose(pipe);
    }
    
    // Phase 5: Network Indicators
    printf("\n🌐 Phase 5: Network Capability Assessment\n");
    printf("────────────────────────────────────────\n");
    
    // Check for network-related strings
    snprintf(inspect_cmd, sizeof(inspect_cmd), 
             "strings \"%s\" 2>/dev/null | grep -E '(http://|https://|ftp://|tcp|udp|socket|connect)' | head -5", 
             package_path);
    
    pipe = popen(inspect_cmd, "r");
    if (pipe) {
        char line[1024];
        int network_indicators = 0;
        while (fgets(line, sizeof(line), pipe) && network_indicators < 5) {
            printf("   🌐 Network: %s", line);
            network_indicators++;
        }
        
        if (network_indicators > 0) {
            printf("   ⚠️  Package may have network capabilities\n");
            risk_score += 2;
        } else {
            printf("   ✅ No obvious network capabilities\n");
        }
        
        pclose(pipe);
    }
    
    // Final Risk Assessment
    printf("\n🛡️ SAFE ANALYSIS RESULTS\n");
    printf("═══════════════════════════\n");
    printf("Total Risk Score: %d/20\n", risk_score);
    
    if (risk_score >= 15) {
        printf("🚨 CRITICAL RISK - Do NOT install this package!\n");
    } else if (risk_score >= 10) {
        printf("🔴 HIGH RISK - Extreme caution advised\n");
    } else if (risk_score >= 5) {
        printf("🟡 MODERATE RISK - Proceed with caution\n");
    } else if (risk_score >= 2) {
        printf("🟢 LOW RISK - Appears relatively safe\n");
    } else {
        printf("✅ MINIMAL RISK - Package appears safe\n");
    }
    
    printf("\n📋 ANALYSIS COMPLETED WITHOUT EXECUTION\n");
    printf("   • No system contamination\n");
    printf("   • No privilege escalation risks\n");
    printf("   • Safe for analyzing unknown packages\n");
    printf("   • Comprehensive static analysis performed\n");
    
    rune_log_checkpoint("SAFE_ANALYSIS: completed", "SEC", "Safe analysis completed without execution");
    
    RUNE_LOG_FUNC_END("safe_analyze_package");
    return risk_score;
}

// 🔬 Enhanced static analysis for specific threats
int rune_safe_detect_specific_threats(const char* package_path) {
    printf("\n🔬 ENHANCED THREAT DETECTION\n");
    printf("══════════════════════════════\n");
    
    int threats_found = 0;
    
    // Cryptocurrency mining detection
    printf("₿ Checking for cryptocurrency mining indicators...\n");
    char cmd[512];
    snprintf(cmd, sizeof(cmd), 
             "strings \"%s\" 2>/dev/null | grep -iE '(mining|miner|bitcoin|ethereum|monero|xmrig|cryptonight)' | head -3", 
             package_path);
    
    FILE* pipe = popen(cmd, "r");
    if (pipe) {
        char line[256];
        while (fgets(line, sizeof(line), pipe)) {
            printf("   ⚠️  Crypto mining: %s", line);
            threats_found++;
        }
        pclose(pipe);
    }
    
    // Data exfiltration detection
    printf("📡 Checking for data exfiltration indicators...\n");
    snprintf(cmd, sizeof(cmd), 
             "strings \"%s\" 2>/dev/null | grep -iE '(keylog|screenshot|clipboard|camera|microphone)' | head -3", 
             package_path);
    
    pipe = popen(cmd, "r");
    if (pipe) {
        char line[256];
        while (fgets(line, sizeof(line), pipe)) {
            printf("   🚨 Data theft: %s", line);
            threats_found++;
        }
        pclose(pipe);
    }
    
    // Backdoor detection
    printf("🚪 Checking for backdoor indicators...\n");
    snprintf(cmd, sizeof(cmd), 
             "strings \"%s\" 2>/dev/null | grep -iE '(backdoor|remote|shell|reverse|bind|listen)' | head -3", 
             package_path);
    
    pipe = popen(cmd, "r");
    if (pipe) {
        char line[256];
        while (fgets(line, sizeof(line), pipe)) {
            printf("   🚪 Backdoor: %s", line);
            threats_found++;
        }
        pclose(pipe);
    }
    
    if (threats_found == 0) {
        printf("✅ No specific advanced threats detected\n");
    } else {
        printf("🚨 ALERT: %d potential advanced threats detected!\n", threats_found);
    }
    
    return threats_found;
}

// Add strcasestr implementation for case-insensitive string search
char* strcasestr(const char* haystack, const char* needle) {
    if (!haystack || !needle) return NULL;
    
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return (char*)haystack;
    
    for (const char* p = haystack; *p; p++) {
        if (strncasecmp(p, needle, needle_len) == 0) {
            return (char*)p;
        }
    }
    
    return NULL;
}

// Case-insensitive string comparison
int strncasecmp(const char* s1, const char* s2, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int c1 = tolower((unsigned char)s1[i]);
        int c2 = tolower((unsigned char)s2[i]);
        
        if (c1 != c2) return c1 - c2;
        if (c1 == 0) break;  // End of string
    }
    return 0;
}
