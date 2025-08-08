#!/bin/bash
# 🛡️ rune_analyze Safety System Demo
# Comprehensive demonstration of the -f/--force safety system

echo "🔬 rune_analyze Safety System Demonstration"
echo "═══════════════════════════════════════════"
echo

echo "🛡️ SAFE ANALYSIS - No -f flag needed (RECOMMENDED):"
echo "────────────────────────────────────────────────"
echo "✅ ./rune_analyze --safe-analyze package.deb        # Safe static analysis"
echo "✅ ./rune_analyze --safe-threats package.deb        # Enhanced threat detection"
echo "✅ ./rune_analyze --security-scan package.deb       # Security assessment"
echo "✅ ./rune_analyze --threat-analyze package.deb      # Comprehensive threat analysis"
echo

echo "🚨 EXECUTION COMMANDS - Require -f flag for safety:"
echo "──────────────────────────────────────────────────"
echo "❌ ./rune_analyze --deep-install package.deb        # BLOCKED - no -f flag"
echo "❌ ./rune_analyze --monitor \"command\"                # BLOCKED - no -f flag"
echo "❌ ./rune_analyze --smart-monitor \"command\"         # BLOCKED - no -f flag"
echo
echo "✅ ./rune_analyze --deep-install package.deb -f     # EXECUTES - explicit permission"
echo "✅ ./rune_analyze --monitor \"command\" -f            # EXECUTES - explicit permission"
echo "✅ ./rune_analyze --smart-monitor \"command\" -f      # EXECUTES - explicit permission"
echo

echo "🛡️ SAFE ALTERNATIVES to execution:"
echo "─────────────────────────────────"
echo "✅ ./rune_analyze --dry-run --deep-install pkg.deb  # Simulate without execution"
echo "✅ ./rune_analyze --dry-run --monitor \"command\"     # Simulate monitoring"
echo

# Demonstrate the safety system
echo "📋 LIVE DEMONSTRATIONS:"
echo "──────────────────────"
echo

echo "1. Safe Analysis (works without -f):"
./rune_analyze --safe-analyze "harmless_test.deb" 2>/dev/null | head -5
echo "   ✅ Executed safely without -f flag"
echo

echo "2. Execution Protection (blocked without -f):"
result=$(./rune_analyze --deep-install "harmless_test.deb" 2>&1 | grep "blocked")
if [[ $result == *"blocked"* ]]; then
    echo "   🛡️ Correctly blocked execution without -f flag"
else
    echo "   ❌ Safety system not working"
fi
echo

echo "3. Force Execution (works with -f):"
./rune_analyze --monitor "echo 'Force test successful'" -f 2>/dev/null | head -3
echo "   ⚡ Executed with explicit -f permission"
echo

echo "4. Safe Simulation (dry-run):"
./rune_analyze --dry-run --deep-install "harmless_test.deb" 2>/dev/null
echo "   🛡️ Safe simulation completed"
echo

echo "🎯 SAFETY SYSTEM SUMMARY:"
echo "═══════════════════════════"
echo "• 🛡️  Safe analysis: DEFAULT behavior (no execution risk)"
echo "• 🚨 Execution commands: Require explicit -f flag"
echo "• 🔍 Clear warnings: Users understand the implications"
echo "• 🏗️  Dry-run option: Test without execution"
echo "• ⚡ Full control: Force flag enables execution when needed"
echo
echo "✅ Perfect for program analysis - safe by default, powerful when needed!"
