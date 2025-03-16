#!/bin/bash

# Build the project
echo "Building project..."
mkdir -p build
cd build
cmake ..
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

# Run simulation scenarios
echo "Running urban scenario simulation..."
./waf --run "scenarios/urban-scenario \
    --numVehicles=50 \
    --numMalicious=5 \
    --simTime=300"

if [ $? -ne 0 ]; then
    echo "Simulation failed!"
    exit 1
fi

# Create results directory
mkdir -p ../results

# Analyze results
echo "Analyzing results..."
cd ..
python3 analysis/analyze_results.py \
    build/vanet-trace.tr \
    --output-dir results \
    --report-file results/report.txt

if [ $? -ne 0 ]; then
    echo "Analysis failed!"
    exit 1
fi

echo "Simulation and analysis completed successfully!"
echo "Results are available in the 'results' directory"
echo "View the report at results/report.txt" 