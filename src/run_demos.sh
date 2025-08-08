#!/bin/bash
# Demo Runner for Reorganized rune_analyze
echo "🎭 RUNE_ANALYZE DEMO RUNNER"
echo "==========================="
echo "Available demos:"
echo "  1. Safety Demo"
echo "  2. Intelligence Demo"  
echo "  3. Complete Features Demo"
echo "  4. Clean for GitHub"
echo

case "$1" in
    "1"|"safety")
        echo "🛡️ Running Safety Demo..."
        cd src && ./safety_demo.sh
        ;;
    "2"|"intelligence") 
        echo "🧠 Running Intelligence Demo..."
        cd src && ./intelligent_demo.sh
        ;;
    "3"|"features")
        echo "🚀 Running Complete Features Demo..."
        cd src && ./COMPLETE_FEATURES_DEMO.sh
        ;;
    "4"|"clean")
        echo "🧹 Running GitHub Clean..."
        cd src && ./clean_for_github.sh
        ;;
    *)
        echo "Usage: $0 [1-4|safety|intelligence|features|clean]"
        echo "   or: $0 [demo_name]"
        ;;
esac
