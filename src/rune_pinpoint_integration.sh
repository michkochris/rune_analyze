#!/bin/bash
# Integration script for pinpoint analysis with rune_analyze -v

echo "🎯 RUNE_ANALYZE PINPOINT INTEGRATION"
echo "===================================="
echo "Usage: rune_analyze runepkg somepkg.deb -v"
echo "       ↓"
echo "Provides surgical analysis with:"
echo "  📁 File: runepkg_defensive.c"
echo "  🎯 Function: runepkg_secure_malloc()"  
echo "  📍 Line: 20"
echo "  📝 Issue: Memory leak potential"
echo "  💡 Fix: Add proper memory management"
echo

if [ "$1" = "runepkg" ] && [ "$3" = "-v" ]; then
    echo "🔍 VERBOSE MODE DETECTED - Running pinpoint analysis..."
    ./pinpoint_demo
else
    echo "💡 To see pinpoint analysis, use:"
    echo "   ./rune_analyze runepkg somepkg.deb -v"
    echo
    echo "🔧 Current demo available:"
    echo "   ./pinpoint_demo"
fi
