# ⚡ Quick Reference & Developer Guide

## **Essential Commands**

### **Basic Analysis**
```bash
# Single file analysis with surgical precision
./rune_analyze -v source.c

# Directory analysis  
./rune_analyze -v /path/to/codebase/

# Very verbose mode with comprehensive details
./rune_analyze -vv source.c

# JSON output for automation
./rune_analyze --json -v source.c
```

### **Package Security Assessment**
```bash
# Safe package analysis (no execution)
./rune_analyze --safe-analyze package.deb

# Package installation with analysis
./rune_analyze package.deb -i package.deb
```

---

## **Build & Development**

### **Build Commands**
```bash
# Standard build
make clean && make

# Debug build with sanitizers  
make debug

# Performance optimized build
make release

# Run tests
make test
```

### **Development Workflow**
```bash
# Development cycle
make dev    # clean + debug + test

# Code formatting
make format

# Performance benchmarking
make benchmark

# Interactive demo
make demo
```

---

## **Output Format Examples**

### **Human-Readable Output**
```
🎯 PINPOINT ANALYSIS REPORT
===========================
🔴 [CRITICAL] BUFFER_OVERFLOW_RISK
  📁 File: runepkg_defensive.c  
  🎯 Function: runepkg_secure_strcpy()
  📍 Line: 183
  📝 Issue: Unsafe string function usage
  💡 Fix: Replace with strncpy()
```

### **JSON Output**  
```json
{
  "findings": [{
    "severity": "CRITICAL",
    "type": "BUFFER_OVERFLOW_RISK",
    "file": "runepkg_defensive.c",
    "function": "runepkg_secure_strcpy", 
    "line": 183,
    "fix": "Replace with strncpy()"
  }]
}
```

---

## **Integration Examples**

### **CI/CD Pipeline Integration**
```yaml
# GitHub Actions
- name: Security Analysis
  run: |
    make clean && make
    ./rune_analyze --json src/ > security-report.json
    python parse_security_results.py security-report.json
```

### **Pre-commit Hook**
```bash
#!/bin/bash
# .git/hooks/pre-commit
./rune_analyze --json --quiet $(git diff --cached --name-only "*.c") > /tmp/security-check.json
if [ -s /tmp/security-check.json ]; then
    echo "Security issues detected. Please review:"
    cat /tmp/security-check.json
    exit 1
fi
```

---

## **Advanced Usage Patterns**

### **Batch Processing**
```bash
# Analyze entire codebase with progress
find . -name "*.c" | while read file; do
    echo "Analyzing: $file"
    ./rune_analyze -v "$file" >> analysis-results.txt
done
```

### **Research Mode**
```bash
# Comprehensive analysis with timing data
./rune_analyze --research-mode --timing-data codebase/ > research-data.json

# Benchmark against test suite  
./rune_analyze --validate-against test-suite/ > validation-results.json
```

---

## **Configuration Options**

### **Environment Variables**
```bash
export RUNE_ANALYZE_CONFIG="/path/to/custom.config"
export RUNE_ANALYZE_VERBOSE=2  # Very verbose by default
export RUNE_ANALYZE_OUTPUT="json"  # Default output format
```

### **Command Line Flags**
```
-v, --verbose           Standard verbose mode
-vv, --very-verbose     Deep analysis mode  
-q, --quiet             Minimal output
--json                  JSON formatted output
--safe-analyze          Package analysis without execution
--benchmark             Performance benchmarking mode
--research-mode         Academic research data collection
```

---

## **Common Use Cases**

### **Security Audit Workflow**
```bash
# 1. Initial assessment
./rune_analyze --json -v codebase/ > initial-assessment.json

# 2. Generate report  
python generate_security_report.py initial-assessment.json

# 3. Track remediation progress
./rune_analyze --json -v codebase/ > post-fix-assessment.json
python compare_assessments.py initial-assessment.json post-fix-assessment.json
```

### **Developer Daily Workflow**
```bash  
# Quick check before commit
./rune_analyze -v $(git diff --name-only "*.c")

# Comprehensive local analysis
./rune_analyze -vv src/

# Integration testing
make test && ./rune_analyze --safe-analyze build/package.deb
```

---

## **Troubleshooting**

### **Common Issues**
```bash
# Build issues
make clean && make  # Clean rebuild usually fixes build problems

# Permission issues
chmod +x rune_analyze  # Ensure executable permissions

# Performance issues  
./rune_analyze -q /path/to/file.c  # Use quiet mode for large files
```

### **Debug Mode**
```bash
# Enable debug output
make debug
./rune_analyze_debug -vv source.c

# Check for memory issues
make debug  # Includes AddressSanitizer
```

---

## **Performance Guidelines**

### **Optimal Usage**
- **Single files**: Use `-v` for detailed analysis
- **Large codebases**: Use `-q` for speed, `--json` for processing
- **CI/CD**: Use `--json --quiet` for fastest automated analysis
- **Research**: Use `--research-mode` for comprehensive data collection

### **Resource Requirements**
```
Memory: <64MB peak for most codebases
CPU: Single-core optimized, <100ms per typical file
Disk: Minimal I/O, works well on network filesystems
```

---

## **Expert Tips**

### **Maximizing Accuracy**
- Analyze **individual files** rather than directories for highest precision
- Use **-vv mode** for comprehensive vulnerability coverage  
- **Combine with manual review** for critical security applications

### **Performance Optimization**  
- **Pre-filter files** to analyze only relevant source code
- **Use JSON output** for automated processing pipelines
- **Batch similar files** together for analysis efficiency

---

*Everything you need for surgical precision static analysis.*
