#!/bin/bash
# Performance Benchmark Runner for Security Library

set -e

echo "========================================="
echo "Security Library Performance Benchmarks"
echo "========================================="
echo ""

# Function to print colored output
print_section() {
    echo ""
    echo ">>> $1"
    echo ""
}

# Check if criterion is installed
if ! grep -q "criterion" Cargo.toml; then
    echo "Error: Criterion not found in Cargo.toml"
    exit 1
fi

# Menu
echo "Select benchmark type:"
echo "1) Quick Criterion benchmarks (fast, good overview)"
echo "2) Full Criterion benchmarks (detailed, takes longer)"
echo "3) Memory + CPU usage benchmarks"
echo "4) All benchmarks"
echo "5) View previous benchmark reports"
echo ""
read -p "Enter choice [1-5]: " choice

case $choice in
    1)
        print_section "Running Quick Criterion Benchmarks"
        cargo bench -- --quick
        echo ""
        echo "To view detailed HTML reports:"
        echo "  open target/criterion/report/index.html"
        ;;
    2)
        print_section "Running Full Criterion Benchmarks"
        cargo bench --bench crypto_benchmarks
        echo ""
        echo "HTML reports available at: target/criterion/report/index.html"
        ;;
    3)
        print_section "Running Memory & CPU Benchmarks"
        cargo bench --bench memory_benchmark
        ;;
    4)
        print_section "Running All Benchmarks"
        echo "This will take several minutes..."
        echo ""
        cargo bench
        echo ""
        echo "HTML reports available at: target/criterion/report/index.html"
        ;;
    5)
        if [ -d "target/criterion/report" ]; then
            if command -v open &> /dev/null; then
                open target/criterion/report/index.html
            elif command -v xdg-open &> /dev/null; then
                xdg-open target/criterion/report/index.html
            else
                echo "Report location: target/criterion/report/index.html"
            fi
        else
            echo "No previous reports found. Run benchmarks first."
        fi
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "========================================="
echo "Benchmark Complete!"
echo "========================================="
echo ""
echo "For more information, see BENCHMARKS.md"
