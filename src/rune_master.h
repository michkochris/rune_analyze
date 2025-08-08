/**
 * rune_master.h - Master Orchestration Functions for rune_analyze
 *
 * THE VISION: rune_analyze as the supreme commander of package operations!
 * 
 * Copyright (C) 2025 Christopher Michko
 * Co-developed with GitHub Copilot AI Assistant
 *
 * Master orchestration - rune_analyze takes full control!
 */

#ifndef RUNE_MASTER_H
#define RUNE_MASTER_H

#include "rune_types.h"

// 🌟 Master Orchestration Functions (THE VISION!)

/**
 * @brief Master-controlled secure installation
 * rune_analyze takes full control of package installation with comprehensive analysis
 * @param package_path Path to the .deb package
 * @return 0 on success, -1 on failure
 */
int rune_master_deep_install(const char* package_path);

/**
 * @brief Pre-installation security analysis
 * Deep security scan before any installation begins
 * @param package_path Path to the .deb package
 * @return 0 if safe, 1 if suspicious, -1 on error
 */
int rune_master_security_scan(const char* package_path);

/**
 * @brief Intelligent command monitoring
 * Smart monitoring with real-time threat detection
 * @param command Command to monitor
 * @return 0 on success, -1 on failure
 */
int rune_master_smart_monitor(const char* command);

/**
 * @brief Comprehensive threat assessment
 * Full threat analysis with vulnerability detection
 * @param package_path Path to the .deb package
 * @return Threat level (0=safe, 10=critical), -1 on error
 */
int rune_master_threat_analyze(const char* package_path);

// Master orchestration helper functions
int rune_master_choose_runepkg_strategy(const char* package_path);
int rune_master_detect_vulnerabilities_realtime(void);
int rune_master_generate_security_report(void);

// 🛡️ NEW: Safe Analysis Functions (Non-Executing)
int rune_safe_analyze_package(const char* package_path);
int rune_safe_detect_specific_threats(const char* package_path);

// Utility functions for safe analysis
char* strcasestr(const char* haystack, const char* needle);
int strncasecmp(const char* s1, const char* s2, size_t n);

#endif // RUNE_MASTER_H
