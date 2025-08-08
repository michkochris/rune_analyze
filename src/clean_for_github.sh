#!/bin/bash
# GitHub Repository Cleanup Script for rune_analyze

echo "�� CLEANING REPOSITORY FOR GITHUB PUSH"
echo "======================================"

# Standard clean
echo "📋 Running make clean..."
make clean

# Remove development/test files
echo "📋 Removing development artifacts..."
rm -f ../*.deb 2>/dev/null && echo "  ✅ Removed .deb test files" || echo "  ℹ️ No .deb files"
rm -f ./rune_json_synergy 2>/dev/null && echo "  ✅ Removed demo executables" || echo "  ℹ️ No demo executables"
rm -f ./test_*.sh 2>/dev/null && echo "  ✅ Removed test scripts" || echo "  ℹ️ No test scripts"
rm -f ../*.txt 2>/dev/null && echo "  ✅ Removed temporary .txt files" || echo "  ℹ️ No .txt files"

echo "✅ Repository cleaned and ready for GitHub push!"
echo "📋 Run 'git status' to verify clean state"
