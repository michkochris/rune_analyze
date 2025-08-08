/**
 * 🛡️ rune_analyze Force Control System - Quick Reference
 * 
 * SAFE-BY-DEFAULT DESIGN with EXPLICIT EXECUTION CONTROL
 */

// ═══════════════════════════════════════════════════════════════
// 🛡️ SAFE COMMANDS (No -f required) - RECOMMENDED FOR ANALYSIS
// ═══════════════════════════════════════════════════════════════

./rune_analyze --safe-analyze package.deb
    ✓ Static analysis without any execution
    ✓ File structure, size, permissions analysis
    ✓ Filename pattern recognition
    ✓ Archive inspection (no extraction)
    ✓ String analysis for threats
    ✓ Network capability detection
    ✓ Risk scoring (0-20 scale)

./rune_analyze --safe-threats package.deb
    ✓ Everything from --safe-analyze PLUS:
    ✓ Cryptocurrency mining detection
    ✓ Data exfiltration indicators
    ✓ Backdoor pattern recognition
    ✓ Advanced threat scoring

./rune_analyze --security-scan package.deb
    ✓ Pre-installation security assessment
    ✓ File size and name pattern analysis
    ✓ Safe static evaluation

./rune_analyze --threat-analyze package.deb
    ✓ Comprehensive threat assessment
    ✓ Multi-layered security analysis
    ✓ Safe evaluation of suspicious packages

// ═══════════════════════════════════════════════════════════════
// 🚨 EXECUTION COMMANDS (Require -f flag) - USE WITH CAUTION
// ═══════════════════════════════════════════════════════════════

./rune_analyze --deep-install package.deb -f
    ⚠️  EXECUTES: Master-controlled installation
    ⚠️  Runs actual runepkg installation
    ⚠️  System modification possible
    ✓ Pre-analysis security scan
    ✓ Intelligent strategy selection
    ✓ Real-time monitoring
    ✓ Post-execution analysis

./rune_analyze --monitor "command" -f
    ⚠️  EXECUTES: Classic Unix monitoring
    ⚠️  Runs the specified command
    ✓ Performance metrics collection
    ✓ Basic execution analysis

./rune_analyze --smart-monitor "command" -f
    ⚠️  EXECUTES: Intelligent monitoring
    ⚠️  Runs command with enhanced monitoring
    ✓ Real-time threat detection
    ✓ Advanced analysis during execution

// ═══════════════════════════════════════════════════════════════
// 🛡️ SAFE SIMULATION (No execution, no -f needed)
// ═══════════════════════════════════════════════════════════════

./rune_analyze --dry-run --deep-install package.deb
    ✓ Simulates installation without execution
    ✓ Shows what would happen
    ✓ No system modification
    ✓ Safe for testing/learning

./rune_analyze --dry-run --monitor "command"
    ✓ Simulates monitoring without execution
    ✓ Safe command analysis

// ═══════════════════════════════════════════════════════════════
// 🚨 SAFETY PROTECTION SYSTEM
// ═══════════════════════════════════════════════════════════════

WITHOUT -f flag on execution commands:
    🛡️ Command blocked with helpful message
    📋 Clear explanation of risks
    ✅ Suggestions for safe alternatives
    🔍 Educational warnings about execution

WITH -f flag on execution commands:
    ⚡ Explicit permission granted
    🚨 Full execution with monitoring
    📊 Comprehensive analysis
    ✅ User takes informed responsibility

// ═══════════════════════════════════════════════════════════════
// 💡 BEST PRACTICES FOR PROGRAM ANALYSIS
// ═══════════════════════════════════════════════════════════════

FOR RESEARCH/ANALYSIS (99% of use cases):
    ✅ Use --safe-analyze or --safe-threats
    ✅ No execution risks
    ✅ Comprehensive static analysis
    ✅ Can analyze malicious packages safely
    ✅ Repeatable, consistent results

FOR CONTROLLED TESTING (1% of use cases):
    ⚠️  Use execution commands with -f flag
    ⚠️  Only in isolated environments
    ⚠️  Only with trusted packages
    ⚠️  Full understanding of risks

FOR LEARNING/EXPLORATION:
    ✅ Use --dry-run options
    ✅ Safe simulation of execution
    ✅ Understanding without risks

// ═══════════════════════════════════════════════════════════════
// 🎯 THE POWER OF EXPLICIT CONTROL
// ═══════════════════════════════════════════════════════════════

BEFORE (dangerous):
    ./rune_analyze package.deb           # Unclear what happens!

AFTER (explicit):
    ./rune_analyze --safe-analyze pkg.deb    # Clearly safe
    ./rune_analyze --deep-install pkg.deb -f # Clearly executes

RESULT:
    ✓ No accidental execution
    ✓ Clear user intent
    ✓ Informed consent
    ✓ Safe by default
    ✓ Powerful when needed
